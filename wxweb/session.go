package wxweb

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdp/qrterminal"
	"golang.org/x/net/publicsuffix"

	"github.com/stn81/httpclient"
	"github.com/stn81/kate/taskengine"
	"github.com/stn81/kate/utils"
	"github.com/stn81/kcookiejar"
	"github.com/stn81/log"
)

var (
	loginCheckMatcher = regexp.MustCompile("window.code=(\\d+)")
	syncCheckMatcher  = regexp.MustCompile("window.synccheck={retcode:\"(\\d+)\",selector:\"(\\d+)\"}")
)

const (
	RetCodeOK              = 0
	RetCodeLogout          = 1100
	RetCodeLoginOtherwhere = 1101
	RetCodeQuitOnPhone     = 1102
)

const (
	TipWaitScanCode = "1"
	TipWaitConfirm  = "0"
)

type SessionCache struct {
	Skey        string
	Sid         string
	Uin         string
	PassTicket  string
	IsGrayScale int
	DataTicket  string
	RedirectURL string
}

type Session struct {
	lang        string
	redirectURI *url.URL
	sessionFile string
	cookieFile  string
	cookieJar   *kcookiejar.Jar

	// mutex protect following fields
	mutex          sync.RWMutex
	skey           string
	sid            string
	uin            string
	isGrayScale    int
	dataTicket     string
	passTicket     string
	syncCheckKey   *SyncCheckKey
	syncKey        *SyncKey
	user           *User
	cgiBaseURL     string
	uploadMediaURL string
	pushURL        string
	contactManager *ContactManager
	// mutext protect end

	// atomic fields
	mediaCount uint32
	// atomic fields end

	handlersLock sync.RWMutex
	handlers     map[int][]*HandlerWrapper

	logged   bool
	quit     chan struct{}
	syncChan chan *WxSyncResp
	engine   *taskengine.TaskEngine
	wg       sync.WaitGroup
	client   *httpclient.Client
	ctx      context.Context
}

func NewSession(ctx context.Context, sessionFile, cookieFile string) *Session {
	// nolint: errcheck
	cookieJar, _ := kcookiejar.New(&kcookiejar.Options{PublicSuffixList: publicsuffix.List, Filename: cookieFile})
	clientOptions := []httpclient.ClientOption{
		httpclient.Timeout(30 * time.Second),
		httpclient.SetCookieJar(cookieJar),
		//httpclient.SetTransport(&http.Transport{
		//Proxy: http.ProxyFromEnvironment,
		//DialContext: (&net.Dialer{
		//Timeout:   30 * time.Second,
		//KeepAlive: 30 * time.Second,
		//DualStack: true,
		//}).DialContext,
		//MaxIdleConns:          100,
		//IdleConnTimeout:       90 * time.Second,
		//TLSHandshakeTimeout:   30 * time.Second,
		//ExpectContinueTimeout: 30 * time.Second,
		//}),
	}

	session := &Session{
		sessionFile: sessionFile,
		cookieFile:  cookieFile,
		cookieJar:   cookieJar,
		lang:        "zh_",
		handlers:    make(map[int][]*HandlerWrapper),
		quit:        make(chan struct{}),
		syncChan:    make(chan *WxSyncResp, 512),
		engine:      taskengine.New(ctx, "wxhandler", 0),
		ctx:         ctx,
	}
	requestOptions := []httpclient.RequestOption{
		httpclient.SetHeader("User-Agent", UserAgent),
		httpclient.SetHeader("Referer", "https://wx.qq.com/"),
	}
	client := httpclient.New(ctx, clientOptions...)
	client.SetDefaultReqOpts(requestOptions...)
	client.SetRetry([]time.Duration{300 * time.Millisecond, time.Second})
	session.client = client
	return session
}

func (session *Session) RegisterHandler(name string, msgType int, handler Handler) {
	wrapper := &HandlerWrapper{
		Name:    name,
		Enabled: true,
		Handler: handler,
	}
	session.handlersLock.Lock()
	handlers := session.handlers[msgType]
	if handlers == nil {
		handlers = make([]*HandlerWrapper, 0, 2)
	}
	handlers = append(handlers, wrapper)
	session.handlers[msgType] = handlers
	session.handlersLock.Unlock()
	log.Info(session.ctx, "handler registered successfully", "name", name)
}

func (session *Session) UnregisterHandler(name string) {
	found := false

	session.handlersLock.Lock()
outerLoop:
	for msgType, handlers := range session.handlers {
		for i := 0; i < len(handlers); i++ {
			if handlers[i].Name == name {
				handlers = append(handlers[:i], handlers[i+1:]...)
				session.handlers[msgType] = handlers
				found = true
				break outerLoop
			}
		}
	}
	session.handlersLock.Unlock()

	if found {
		log.Info(session.ctx, "handler unregistered successfully", "name", name)
	} else {
		log.Warning(session.ctx, "unregister handler: not found", "name", name)
	}
}

func (session *Session) EnableHandler(name string) {
	handler := session.findHandler(name)
	if handler != nil {
		handler.Enabled = true
		log.Info(session.ctx, "handler enabled", "name", name)
	} else {
		log.Warning(session.ctx, "enable handler: not found", "name", name)
	}
}

func (session *Session) DisableHandler(name string) {
	handler := session.findHandler(name)
	if handler != nil {
		handler.Enabled = false
		log.Info(session.ctx, "handler disabled", "name", name)
	} else {
		log.Warning(session.ctx, "disable handler", "name", name)
	}
}

func (session *Session) findHandler(name string) (result *HandlerWrapper) {
	session.handlersLock.RLock()
	for _, handlers := range session.handlers {
		for _, handler := range handlers {
			if handler.Name == name {
				result = handler
				break
			}
		}
	}
	session.handlersLock.RUnlock()
	return result
}

func (session *Session) getHandlersByMsgType(msgType int) (handlers []*HandlerWrapper) {
	session.handlersLock.RLock()
	if registeredHandlers := session.handlers[msgType]; len(registeredHandlers) > 0 {
		handlers = make([]*HandlerWrapper, len(registeredHandlers))
		copy(handlers, registeredHandlers)
	}
	session.handlersLock.RUnlock()
	return handlers
}

func (session *Session) LoginAndServe() error {
	var (
		uuid     string
		useCache bool
		err      error
		skipScan = true
	)

	session.prepareDir()

	if useCache, err = session.loadFromFile(); err != nil {
		log.Error(session.ctx, "load session from cache file",
			"cache_file", session.sessionFile, "error", err)
	}

	session.wg.Add(1)
	go session.handleLoop()

	for {
		session.logged = false
		if !useCache {
			for {
				if session.redirectURI != nil {
					oldCookies := session.cookieJar.Cookies(session.redirectURI)
					cookies := []*http.Cookie{
						{Name: "login_frequency", Value: "2"},
						{Name: "last_wxuin", Value: session.uin},
						{Name: "MM_WX_NOTIFY_STATE", Value: "1"},
						{Name: "MM_WX_SOUND_STATE", Value: "1"},
					}

					wxloadtime := getCookie(oldCookies, "wxloadtime")
					if wxloadtime != nil {
						cookies = append(cookies,
							&http.Cookie{Name: "wxloadtime", Value: wxloadtime.Value + "_expired"},
							&http.Cookie{Name: "wxpluginkey", Value: wxloadtime.Value},
						)
					}
					session.cookieJar.SetCookies(session.redirectURI, cookies)
				}
				if session.uin != "" && skipScan {
					if uuid, err = session.pushLoginURL(session.uin); err != nil {
						log.Error(session.ctx, "pushloginurl failed", "erorr", err)
						skipScan = false
						continue
					}
					fmt.Println("please confirm on the phone to login")
				} else {
					if uuid, err = session.getLoginUUID(); err != nil {
						log.Error(session.ctx, "jslogin failed", "erorr", err)
						continue
					}
					session.displayQRCode(uuid)
					fmt.Println("please scan the QR code to continue login")
				}

				if err = session.waitLogin(uuid); err != nil {
					log.Error(session.ctx, "wait for user login", "error", err)
					continue
				}

				log.Info(session.ctx, "user logon successfully")

				if err = session.doRedirectLogin(); err != nil {
					log.Error(session.ctx, "redirect login failed", "error", err)
					continue
				}
				log.Info(session.ctx, "redirect login successfully")
				break
			}
		}

		if err = session.wxInit(); err != nil {
			log.Error(session.ctx, "wxinit failed, restart login", "error", err)
			if IsBizError(err) {
				useCache = false
			}
			continue
		}

		fmt.Println("weixin web logged in successfully")
		log.Info(session.ctx, "wxinit successfully")
		skipScan = true
		useCache = true
		session.logged = true

		if err = session.flushToFile(); err != nil {
			log.Error(session.ctx, "flushToFile session cache failed", "error", err)
		}

		if err = session.statusNotify(); err != nil {
			log.Error(session.ctx, "status notify failed", "error", err)
			if IsBizError(err) {
				useCache = false
			}
			continue
		}
		log.Info(session.ctx, "status notify successfully")

		if err = session.getContact(); err != nil {
			log.Error(session.ctx, "get contact failed", "error", err)
			if IsBizError(err) {
				useCache = false
			}
			continue
		}
		log.Info(session.ctx, "get contact successfully")

		if err = session.syncLoop(); err != nil {
			log.Error(session.ctx, "syncLoop", "error", err)
			if IsBizError(err) {
				useCache = false
			}
			continue
		}

		// session quit
		log.Info(session.ctx, "serve loop quit")
		break
	}
	return nil
}

func (session *Session) Quit() {
	close(session.quit)
	session.wg.Wait()
	session.engine.Shutdown()

	if session.logged {
		if err := session.logout(); err != nil {
			log.Error(session.ctx, "logout failed", "error", err)
		}
	}

	log.Info(session.ctx, "session quit")
}

func (session *Session) pushLoginURL(uin string) (uuid string, err error) {
	q := url.Values{}
	q.Add("uin", uin)

	pushLoginURLResp := &PushLoginURLResp{}
	err = session.client.NewJSON().Get(session.getCGIBaseURL()+"/webwxpushloginurl", "", pushLoginURLResp, httpclient.SetQuery(q))
	if err != nil {
		return "", err
	}

	if pushLoginURLResp.Ret != "0" {
		err = NewBizError("pushloginurl: ret=%v, msg=%v", pushLoginURLResp.Ret, pushLoginURLResp.Msg)
		return "", err
	}
	return pushLoginURLResp.UUID, nil
}

func (session *Session) getLoginUUID() (uuid string, err error) {
	q := url.Values{}
	q.Add("appid", AppID)
	q.Add("fun", "new")
	q.Add("lang", "zh_CN")
	q.Add("redirect_uri", "")
	q.Add("_", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))

	result, err := session.client.Get(LoginBaseURL+"/jslogin", "", httpclient.SetQuery(q))
	if err != nil {
		return "", err
	}

	ss := strings.Split(result, "\"")
	if len(ss) < 2 {
		return "", NewBizError("invalid jslogin response: %s", result)
	}
	return ss[1], nil
}

func (session *Session) displayQRCode(uuid string) {
	qrterminal.Generate("https://login.weixin.qq.com/l/"+uuid, qrterminal.L, os.Stdout)
}

func (session *Session) waitLogin(uuid string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	tip := TipWaitScanCode
loop:
	for range ticker.C {
		code, err := session.checkLogin(uuid, tip)
		if err != nil {
			log.Error(session.ctx, "check qrcode scanned", "uuid", uuid, "error", err)
			return err
		}

		switch code {
		case 200:
			// user logon success
			break loop
		case 201:
			// user scanned code, wait confirm
			tip = TipWaitConfirm
		case 408:
			// timeout
			log.Warning(session.ctx, "wait for user login timeout")
			return NewBizError("wait login timeout")
		default:
			// other error
			return NewBizError("wait login error: code=%v", code)
		}
	}
	return nil
}

func (session *Session) checkLogin(uuid string, tip string) (code int, err error) {
	q := url.Values{}
	q.Add("tip", tip)
	q.Add("uuid", uuid)
	q.Add("r", strconv.FormatInt(int64(^int32(utils.Milliseconds(time.Now()))), 10))
	q.Add("_", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))
	q.Add("loginicon", "true")

	result, err := session.client.Get(LoginBaseURL+"/cgi-bin/mmwebwx-bin/login", "", httpclient.SetQuery(q))
	if err != nil {
		return -1, err
	}

	matched := loginCheckMatcher.FindStringSubmatch(result)
	if len(matched) < 2 {
		return -1, NewBizError("login failed: %v", result)
	}
	code = utils.GetInt(matched[1])
	if code != 200 {
		return code, nil
	}

	ss := strings.Split(result, "\"")
	if len(ss) < 2 {
		return code, NewBizError("get redirect_uri failed: %s", result)
	}

	if err = session.setRedirectURI(ss[1] + "&fun=new"); err != nil {
		return code, err
	}

	log.Debug(session.ctx, "get redirect_uri success")

	return code, nil
}

func (session *Session) setRedirectURI(uri string) (err error) {
	session.redirectURI, err = url.Parse(uri)
	if err != nil {
		return NewBizError("parse redirect_uri failed: %s", uri)
	}

	domain := DefaultDomainList.GetDomain(session.redirectURI.Host)
	if domain == nil {
		log.Error(session.ctx, "domain not recognized", "redirect_uri", uri)
		domain = DefaultDomainList[0]
	}

	session.cgiBaseURL = session.redirectURI.Scheme + "://" + session.redirectURI.Host + "/cgi-bin/mmwebwx-bin"
	session.uploadMediaURL = session.redirectURI.Scheme + "://" + domain.File + "/cgi-bin/mmwebwx-bin/webwxuploadmedia"
	session.pushURL = session.redirectURI.Scheme + "://" + domain.Push + "/cgi-bin/mmwebwx-bin/synccheck"
	return nil
}

func (session *Session) doRedirectLogin() error {
	resp := &RedirectLoginResp{}
	if err := session.client.NewXML().Get(session.redirectURI.String(), "", resp); err != nil {
		return err
	}

	if resp.Ret != 0 {
		err := NewBizError("login failed: ret=%v, errmsg=%s", resp.Ret, resp.Message)
		log.Error(session.ctx, "redirectlogin failed", "error", err)
		return err
	}

	session.mutex.Lock()
	session.skey = resp.Skey
	session.sid = resp.WxSID
	session.uin = resp.WxUIN
	session.passTicket = resp.PassTicket
	session.isGrayScale = resp.IsGrayscale
	session.updateDataTicketUnlocked()
	session.mutex.Unlock()

	log.Debug(session.ctx, "login success",
		"skey", session.skey,
		"wxsid", session.sid,
		"wxuin", session.uin,
		"pass_ticket", session.passTicket,
		"is_gray_scale", session.isGrayScale,
	)
	return nil
}

func (session *Session) wxInit() error {
	q := url.Values{}
	q.Add("pass_ticket", session.getPassTicket())
	q.Add("skey", session.getSkey())
	q.Add("r", strconv.FormatInt(int64(^int32(utils.Milliseconds(time.Now()))), 10))

	wxInitReq := &WxInitReq{
		BaseRequest: session.getBaseRequest(),
	}

	wxInitResp := &WxInitResp{}
	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"/webwxinit", wxInitReq, wxInitResp, httpclient.SetQuery(q))
	if err != nil {
		return err
	}

	if wxInitResp.BaseResponse.Ret != 0 {
		return NewBizError("wxinit failed: ret=%v, errmsg=%v", wxInitResp.BaseResponse.Ret, wxInitResp.BaseResponse.ErrMsg)
	}

	session.mutex.Lock()
	session.user = wxInitResp.User
	session.syncKey = wxInitResp.SyncKey
	session.mutex.Unlock()
	return nil
}

func (session *Session) statusNotify() error {
	q := url.Values{}
	q.Add("pass_ticket", session.getPassTicket())

	user := session.GetUser()
	statusNotifyReq := &WxStatusNotifyReq{
		BaseRequest:  session.getBaseRequest(),
		ClientMsgId:  utils.Milliseconds(time.Now()),
		Code:         3,
		FromUserName: user.UserName,
		ToUserName:   user.UserName,
	}

	statusNotifyResp := &WxStatusNotifyResp{}
	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"/webwxstatusnotify", statusNotifyReq, statusNotifyResp, httpclient.SetQuery(q))
	if err != nil {
		return err
	}

	if statusNotifyResp.BaseResponse.Ret != 0 {
		return NewBizError("statusnotify failed: ret=%v, errmsg=%v",
			statusNotifyResp.BaseResponse.Ret, statusNotifyResp.BaseResponse.ErrMsg)
	}
	return nil
}

func (session *Session) getContact() error {
	q := url.Values{}
	q.Add("pass_ticket", session.getPassTicket())
	q.Add("r", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))
	q.Add("seq", "0")
	q.Add("skey", session.getSkey())

	getContactResp := &WxGetContactResp{}
	err := session.client.NewJSON().Get(session.getCGIBaseURL()+"/webwxgetcontact", nil, getContactResp, httpclient.SetQuery(q))
	if err != nil {
		return err
	}

	if getContactResp.BaseResponse.Ret != 0 {
		return NewBizError("getcontact failed: ret=%v, errmsg=%v",
			getContactResp.BaseResponse.Ret, getContactResp.BaseResponse.ErrMsg)
	}

	session.mutex.Lock()
	session.contactManager = NewContactManager(getContactResp.MemberList)
	session.mutex.Unlock()

	return nil
}

func (session *Session) batchGetContact() error {
	//q := url.Values{}
	//q.Add("type", "ex")
	//q.Add("r", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))
	//q.Add("r", session.passTicket)
	return nil
}

func (session *Session) syncCheck() (ret int, selector int, err error) {
	q := url.Values{}
	q.Add("r", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))
	q.Add("sid", session.getSid())
	q.Add("uin", session.getUin())
	q.Add("skey", session.getSkey())
	q.Add("deviceid", session.getDeviceID())
	q.Add("synckey", session.getSyncKey().String())
	q.Add("_", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))

	result, err := session.client.Get(session.getPushURL(), "", httpclient.SetQuery(q))
	if err != nil {
		return 0, 0, err
	}

	matched := syncCheckMatcher.FindStringSubmatch(result)
	if len(matched) < 3 {
		return 0, 0, NewBizError("unknown synccheck result: %v", result)
	}

	ret = utils.GetInt(matched[1])
	selector = utils.GetInt(matched[2])

	return ret, selector, nil
}

func (session *Session) sync() error {
	q := url.Values{}
	q.Add("sid", session.getSid())
	q.Add("skey", session.getSkey())
	q.Add("pass_ticket", session.getPassTicket())

	syncReq := &WxSyncReq{
		BaseRequest: session.getBaseRequest(),
		RR:          ^int32(utils.Milliseconds(time.Now())),
		SyncKey:     session.getSyncKey(),
	}

	syncResp := &WxSyncResp{}
	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"/webwxsync", syncReq, syncResp, httpclient.SetQuery(q))
	if err != nil {
		return err
	}

	if syncResp.BaseResponse.Ret != 0 {
		err = NewBizError("sync failed: ret=%v, errmsg=%v",
			syncResp.BaseResponse.Ret, syncResp.BaseResponse.ErrMsg)
		log.Error(session.ctx, "sync failed", "error", err)
		return err
	}

	session.mutex.Lock()
	session.syncKey = syncResp.SyncKey
	session.syncCheckKey = syncResp.SyncCheckKey
	session.updateDataTicketUnlocked()
	session.mutex.Unlock()

	session.syncChan <- syncResp
	return nil
}

func (session *Session) logout() error {
	q := url.Values{}
	q.Add("redirect", "1")
	q.Add("type", "1")
	q.Add("skey", session.getSkey())

	f := url.Values{}
	f.Add("sid", session.getSid())
	f.Add("uid", session.getUin())

	_, err := session.client.Post(session.getCGIBaseURL()+"webwxlogout", f.Encode(), httpclient.SetQuery(q), httpclient.SetTypeForm())
	if err != nil {
		if httpErr, ok := err.(*httpclient.HTTPError); ok && httpErr.StatusCode == 301 {
			return nil
		}
		log.Error(session.ctx, "logout failed", "error", err)
		return err
	}
	return nil
}

func (session *Session) SendMsg(toUserName, msg string) error {
	q := url.Values{}
	q.Add("pass_ticket", session.getPassTicket())
	q.Add("lang", session.lang)

	fromUserName := session.GetUser().UserName

	localID := session.nextMessageID()
	sendMsgReq := &WxSendMsgReq{
		BaseRequest: session.getBaseRequest(),
		Msg: TextMessage{
			Type:         1,
			Content:      msg,
			FromUserName: fromUserName,
			ToUserName:   toUserName,
			LocalID:      localID,
			ClientMsgId:  localID,
		},
	}
	sendMsgResp := &WxSendMsgResp{}

	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"/webwxsendmsg", sendMsgReq, sendMsgResp, httpclient.SetQuery(q))
	if err != nil {
		log.Error(session.ctx, "sendmsg failed",
			"fromUserName", fromUserName,
			"toUserName", toUserName,
			"content", msg,
			"error", err,
		)
		return err
	}

	if sendMsgResp.BaseResponse.Ret != 0 {
		err = NewBizError("sendmsg failed: ret = %v, errmsg=%v", sendMsgResp.BaseResponse.Ret, sendMsgResp.BaseResponse.ErrMsg)
		log.Error(session.ctx, "sendmsg failed",
			"fromUserName", fromUserName,
			"toUserName", toUserName,
			"content", msg,
			"error", err,
		)
		return err
	}
	return nil
}

func (session *Session) SendMsgImg(toUserName, mediaID string) error {
	q := url.Values{}
	q.Add("f", "json")
	q.Add("fun", "async")
	q.Add("lang", session.lang)
	q.Add("pass_ticket", session.getPassTicket())

	fromUserName := session.GetUser().UserName
	localID := session.nextMessageID()
	sendImgMsgReq := &WxSendImgMsgReq{
		BaseRequest: session.getBaseRequest(),
		Msg: ImageMessage{
			Type:         3,
			MediaId:      mediaID,
			Content:      "",
			FromUserName: fromUserName,
			ToUserName:   toUserName,
			LocalID:      localID,
			ClientMsgId:  localID,
		},
		Scene: 0,
	}
	sendImgMsgResp := &WxSendImgMsgResp{}
	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"webwxsendmsgimg", sendImgMsgReq, sendImgMsgResp, httpclient.SetQuery(q))
	if err != nil {
		log.Error(session.ctx, "sendmsgimg failed",
			"fromUserName", fromUserName,
			"toUserName", toUserName,
			"media_id", mediaID,
			"error", err,
		)
		return err
	}

	if sendImgMsgResp.BaseResponse.Ret != 0 {
		err = NewBizError("sendmsgimg: ret=%v, errmsg=%v",
			sendImgMsgResp.BaseResponse.Ret, sendImgMsgResp.BaseResponse.ErrMsg)
		log.Error(session.ctx, "sendmsgimg failed",
			"fromUserName", fromUserName,
			"toUserName", toUserName,
			"media_id", mediaID,
			"error", err,
		)
		return err
	}
	return nil
}

func (session *Session) SendEmoticon(toUserName, mediaID string) error {
	q := url.Values{}
	q.Add("fun", "sys")
	q.Add("lang", session.lang)
	q.Add("pass_ticket", session.getPassTicket())

	fromUserName := session.GetUser().UserName
	localID := session.nextMessageID()
	sendEmoticonReq := &WxSendEmoticonReq{
		BaseRequest: session.getBaseRequest(),
		Msg: EmoticonMessage{
			Type:         47,
			EmojiFlag:    2,
			MediaId:      mediaID,
			FromUserName: fromUserName,
			ToUserName:   toUserName,
			LocalID:      localID,
			ClientMsgId:  localID,
		},
	}
	sendEmoticonResp := &WxSendEmoticonResp{}

	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"webwxsendemoticon", sendEmoticonReq, sendEmoticonResp, httpclient.SetQuery(q))
	if err != nil {
		log.Error(session.ctx, "sendemoticon failed",
			"fromUserName", fromUserName,
			"toUserName", toUserName,
			"media_id", mediaID,
			"error", err,
		)
		return err
	}

	if sendEmoticonResp.BaseResponse.Ret != 0 {
		err = NewBizError("sendemoticon: ret=%v, errmsg=%v",
			sendEmoticonResp.BaseResponse.Ret, sendEmoticonResp.BaseResponse.ErrMsg)
		log.Error(session.ctx, "sendemoticon failed",
			"fromUserName", fromUserName,
			"toUserName", toUserName,
			"media_id", mediaID,
			"error", err,
		)
		return err
	}
	return nil
}

func (session *Session) UploadMedia(filename string, content []byte) (mediaID string, err error) {
	buf := &bytes.Buffer{}

	mw := multipart.NewWriter(buf)
	defer func() {
		if err = mw.Close(); err != nil {
			log.Error(session.ctx, "uploadmedia: close multipart writer", "error", err)
		}
	}()

	formFile, err := mw.CreateFormFile("filename", filename)
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form file", "filename", filename, "error", err)
		return "", err
	}

	if _, err = io.Copy(formFile, bytes.NewReader(content)); err != nil {
		log.Error(session.ctx, "uploadmedia: io.Copy", "filename", filename, "error", err)
		return "", err
	}

	ss := strings.Split(filename, ".")
	if len(ss) != 2 {
		return "", fmt.Errorf("file type suffix not found")
	}
	suffix := ss[1]

	idField, err := mw.CreateFormField("id")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `id`", "error", err)
		return "", err
	}
	if _, err = idField.Write([]byte("WU_FILE_" + strconv.Itoa(int(atomic.AddUint32(&session.mediaCount, 1))))); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `id`", "error", err)
		return "", err
	}

	nameField, err := mw.CreateFormField("name")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `name`", "error", err)
		return "", err
	}
	if _, err = nameField.Write([]byte(filename)); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `name`", "error", err)
		return "", err
	}

	typeField, err := mw.CreateFormField("type")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `type`", "error", err)
		return "", err
	}
	if suffix == "gif" {
		_, err = typeField.Write([]byte("image/gif"))
	} else {
		_, err = typeField.Write([]byte("image/jpeg"))
	}
	if err != nil {
		log.Error(session.ctx, "uploadmedia: write field `type`", "error", err)
		return "", err
	}

	modifyDateField, err := mw.CreateFormField("lastModifiedDate")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `lastModifiedDate`", "error", err)
		return "", err
	}
	if _, err = modifyDateField.Write([]byte("Mon Feb 13 2017 17:27:23 GMT+0800 (CST)")); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `lastModifiedDate`", "error", err)
		return "", err
	}

	sizeField, err := mw.CreateFormField("size")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `size`", "error", err)
		return "", err
	}
	if _, err = sizeField.Write([]byte(strconv.Itoa(len(content)))); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `size`", "error", err)
		return "", err
	}

	mediaTypeField, err := mw.CreateFormField("mediatype")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `mediatype`", "error", err)
		return "", err
	}
	if suffix == "gif" {
		_, err = mediaTypeField.Write([]byte("doc"))
	} else {
		_, err = mediaTypeField.Write([]byte("pic"))
	}
	if err != nil {
		log.Error(session.ctx, "uploadmedia: write field `mediatype`", "error", err)
		return "", err
	}

	digest := md5.Sum(content)
	uploadMediaReq := &WxUploadMediaReq{
		BaseRequest:   session.getBaseRequest(),
		ClientMediaId: utils.Milliseconds(time.Now()),
		TotalLen:      len(content),
		StartPos:      0,
		DataLen:       len(content),
		MediaType:     4,
		FileMd5:       hex.EncodeToString(digest[:]),
	}

	reqField, err := mw.CreateFormField("uploadmediarequest")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `uploadmediarequest`", "error", err)
		return "", err
	}
	if _, err = reqField.Write([]byte(utils.ToJSON(uploadMediaReq))); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `uploadmediarequest`", "error", err)
		return "", err
	}

	dataTicketField, err := mw.CreateFormField("webwx_data_ticket")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `webwx_data_ticket`", "error", err)
		return "", err
	}
	if _, err = dataTicketField.Write([]byte(session.getDataTicket())); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `wx_data_ticket`", "error", err)
		return "", err
	}

	passTicketField, err := mw.CreateFormField("pass_ticket")
	if err != nil {
		log.Error(session.ctx, "uploadmedia: create form field `pass_ticket`", "error", err)
		return "", err
	}
	if _, err = passTicketField.Write([]byte(session.passTicket)); err != nil {
		log.Error(session.ctx, "uploadmedia: write field `pass_ticket`", "error", err)
		return "", err
	}

	q := url.Values{}
	q.Add("f", "json")

	reqOpts := []httpclient.RequestOption{
		httpclient.SetQuery(q),
		httpclient.SetHeader("Content-Type", mw.FormDataContentType()),
	}

	uploadMediaResp := &WxUploadMediaResp{}
	err = session.client.NewJSON().Post(session.getUploadMediaURL(), buf.String(), uploadMediaResp, reqOpts...)
	if err != nil {
		log.Error(session.ctx, "uploadmedia: do request", "error", err)
		return "", err
	}

	if uploadMediaResp.BaseResponse.Ret != 0 {
		err = NewBizError("uploadmedia: ret=%v, errmsg=%v",
			uploadMediaResp.BaseResponse.Ret, uploadMediaResp.BaseResponse.ErrMsg)
		log.Error(session.ctx, "uploadmedia: failed response", "error", err)
		return "", err
	}
	return uploadMediaResp.MediaId, nil
}

func (session *Session) VerifyUser(user, ticket string) error {
	q := url.Values{}
	q.Add("r", strconv.FormatInt(utils.Milliseconds(time.Now()), 10))
	q.Add("lang", session.lang)
	q.Add("pass_ticket", session.getPassTicket())

	verifyUserReq := &WxVerifyUserReq{
		BaseRequest:        session.getBaseRequest(),
		OpCode:             3,
		SceneList:          []int{33},
		SceneListCount:     1,
		VerifyContent:      "",
		VerifyUserListSize: 1,
		VerifyUserList: []VerifyUser{
			{
				Value:            user,
				VerifyUserTicket: ticket,
			},
		},
		Skey: session.skey,
	}
	verifyUserResp := &WxVerifyUserResp{}

	err := session.client.NewJSON().Post(session.getCGIBaseURL()+"webwxverifyuser", verifyUserReq, verifyUserResp, httpclient.SetQuery(q))
	if err != nil {
		log.Error(session.ctx, "verifyuser failed", "user", user, "ticket", ticket, "error", err)
		return err
	}

	if verifyUserResp.BaseResponse.Ret != 0 {
		err = NewBizError("verifyuser: ret=%v, errmsg=%v", verifyUserResp.BaseResponse.Ret, verifyUserResp.BaseResponse.ErrMsg)
		log.Error(session.ctx, "verifyuser failed", "user", user, "ticket", ticket, "error", err)
		return err
	}
	return nil
}

func (session *Session) syncLoop() (err error) {
loop:
	for {
		var (
			ret      int
			selector int
		)

		select {
		case <-session.quit:
			break loop
		default:
		}

		for i := 0; i < 10; i++ {
			if ret, selector, err = session.syncCheck(); err != nil {
				if IsBizError(err) {
					return err
				} else {
					log.Error(session.ctx, "synccheck failed", "error", err)
				}
			} else {
				break
			}
		}

		if err != nil {
			return fmt.Errorf("synccheck failed: %v", err)
		}

		switch ret {
		case RetCodeLogout:
			return NewBizError("synccheck failed: web session logout")
		case RetCodeLoginOtherwhere:
			return NewBizError("synccheck failed: web session login elsewhere")
		case RetCodeQuitOnPhone:
			return NewBizError("synccheck failed: web session quit on phone")
		case RetCodeOK:
			if selector <= 0 {
				continue
			}

			for i := 0; i < 5; i++ {
				if err = session.sync(); err != nil {
					if IsBizError(err) {
						return err
					} else {
						continue
					}
				}
			}
		default:
			return NewBizError("synccheck failed: unknown ret=%v", ret)
		}
	}

	return nil
}

func (session *Session) handleLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Error(session.ctx, "panic in handle loop", "stack", utils.GetPanicStack())
		}
		log.Debug(session.ctx, "handle loop exited")
		session.wg.Done()
	}()

	log.Debug(session.ctx, "handle loop started")
	for {
		select {
		case <-session.quit:
			return
		case syncResp := <-session.syncChan:
			if syncResp.AddMsgCount > 0 {
				for _, addMsg := range syncResp.AddMsgList {
					session.handleMsg(addMsg)
				}
			}
			if syncResp.ModContactCount > 0 {
				for _, modContact := range syncResp.ModContactList {
					session.handleModContact(modContact)
				}
			}
			if syncResp.DelContactCount > 0 {
				for _, delContact := range syncResp.DelContactList {
					session.handleDelContact(delContact)
				}
			}
			if syncResp.ModChatRoomMemberCount > 0 {
				for _, modChatRoom := range syncResp.ModChatRoomMemberList {
					session.handleModChatRoom(modChatRoom)
				}
			}
		}
	}
}

func (session *Session) handleMsg(msg *Message) {
	handlers := session.getHandlersByMsgType(msg.MsgType)
	for _, handler := range handlers {
		task := WrapTask(session.ctx, session, msg, handler.Handler)
		session.engine.Schedule(task)
	}
}

func (session *Session) handleModContact(contact *Contact) {
	contactManager := session.getContactManager()
	contactManager.ModContact(contact)
}

func (session *Session) handleDelContact(contact *Contact) {
	contactManager := session.getContactManager()
	contactManager.DelContact(contact)
}

func (session *Session) handleModChatRoom(event interface{}) {
	// nothing to do
}

func (session *Session) updateDataTicketUnlocked() {
	// refresh wx_data_ticket cookie
	cookies := session.client.Jar.Cookies(session.redirectURI)
	for _, cookie := range cookies {
		if cookie.Name == "webwx_data_ticket" {
			session.dataTicket = cookie.Value
			break
		}
	}
}

func (session *Session) nextMessageID() string {
	return strconv.FormatInt(time.Now().Unix()*1e7+rand.Int63n(1e7), 10)
}

func (session *Session) getSyncKey() (syncKey *SyncKey) {
	session.mutex.RLock()
	syncKey = session.syncKey
	session.mutex.RUnlock()
	return syncKey
}

func (session *Session) getSyncCheckKey() (syncCheckKey *SyncCheckKey) {
	session.mutex.RLock()
	syncCheckKey = session.syncCheckKey
	session.mutex.RUnlock()
	return syncCheckKey
}

func (session *Session) getDataTicket() (dataTicket string) {
	session.mutex.RLock()
	dataTicket = session.dataTicket
	session.mutex.RUnlock()
	return dataTicket
}

func (session *Session) getPassTicket() (passTicket string) {
	session.mutex.RLock()
	passTicket = session.passTicket
	session.mutex.RUnlock()
	return passTicket
}

func (session *Session) getSid() (sid string) {
	session.mutex.RLock()
	sid = session.sid
	session.mutex.RUnlock()
	return sid
}

func (session *Session) getSkey() (skey string) {
	session.mutex.RLock()
	skey = session.skey
	session.mutex.RUnlock()
	return skey
}

func (session *Session) getUin() (uin string) {
	session.mutex.RLock()
	uin = session.uin
	session.mutex.RUnlock()
	return uin
}

func (session *Session) GetUser() (user *User) {
	session.mutex.RLock()
	user = session.user
	session.mutex.RUnlock()
	return user
}

func (session *Session) getContactManager() (m *ContactManager) {
	session.mutex.RLock()
	m = session.contactManager
	session.mutex.RUnlock()
	return m
}

func (session *Session) getCGIBaseURL() (value string) {
	session.mutex.RLock()
	value = session.cgiBaseURL
	session.mutex.RUnlock()
	return value
}

func (session *Session) getUploadMediaURL() (value string) {
	session.mutex.RLock()
	value = session.uploadMediaURL
	session.mutex.RUnlock()
	return value
}

func (session *Session) getPushURL() (value string) {
	session.mutex.RLock()
	value = session.pushURL
	session.mutex.RUnlock()
	return value
}

func (session *Session) getDeviceID() string {
	return "e" + utils.RandString(15, utils.Number)
}

func (session *Session) getBaseRequest() (req *BaseRequest) {
	session.mutex.RLock()
	req = &BaseRequest{
		DeviceID: session.getDeviceID(),
		Sid:      session.sid,
		Skey:     session.skey,
		Uin:      session.uin,
	}
	session.mutex.RUnlock()
	return req
}

func (session *Session) prepareDir() {
	sessionDir := path.Dir(session.sessionFile)
	if _, err := os.Stat(sessionDir); err != nil && os.IsNotExist(err) {
		_ = os.MkdirAll(sessionDir, 0777)
	}
	cookieDir := path.Dir(session.cookieFile)
	if _, err := os.Stat(cookieDir); err != nil && os.IsNotExist(err) {
		_ = os.MkdirAll(cookieDir, 0777)
	}
}

func (session *Session) loadFromFile() (ok bool, err error) {
	if session.sessionFile == "" {
		return false, nil
	}

	if _, err = os.Stat(session.sessionFile); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	data, err := ioutil.ReadFile(session.sessionFile)
	if err != nil {
		return false, err
	}
	cache := &SessionCache{}
	if err = utils.ParseJSON(data, cache); err != nil {
		return false, err
	}
	session.mutex.Lock()
	session.skey = cache.Skey
	session.sid = cache.Sid
	session.uin = cache.Uin
	session.passTicket = cache.PassTicket
	session.isGrayScale = cache.IsGrayScale
	session.dataTicket = cache.DataTicket
	_ = session.setRedirectURI(cache.RedirectURL)
	session.mutex.Unlock()
	return true, nil
}

func (session *Session) flushToFile() (err error) {
	if session.sessionFile == "" {
		return nil
	}

	if err = session.cookieJar.Save(); err != nil {
		log.Error(session.ctx, "save cookie to file", "filename", session.cookieFile, "error", err)
		return err
	}

	var cache *SessionCache
	session.mutex.RLock()
	cache = &SessionCache{
		Skey:        session.skey,
		Sid:         session.sid,
		Uin:         session.uin,
		PassTicket:  session.passTicket,
		IsGrayScale: session.isGrayScale,
		DataTicket:  session.dataTicket,
		RedirectURL: session.redirectURI.String(),
	}
	session.mutex.RUnlock()

	cacheDir := path.Dir(session.sessionFile)
	if _, err = os.Stat(cacheDir); err != nil && os.IsNotExist(err) {
		if err = os.Mkdir(cacheDir, 0755); err != nil {
			log.Error(session.ctx, "mkdir cache dir", "cache_dir", cacheDir, "error", err)
			return err
		}
	}

	cacheData := utils.ToJSON(cache)
	if err = ioutil.WriteFile(session.sessionFile, []byte(cacheData), 0666); err != nil {
		log.Error(session.ctx, "save session to file", "filename", session.sessionFile, "error", err)
		return err
	}
	return nil
}
