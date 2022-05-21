package wxweb

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

type RedirectLoginResp struct {
	XMLName     xml.Name `xml:"error"`
	Ret         int      `xml:"ret"`
	Message     string   `xml:"message"`
	Skey        string   `xml:"skey"`
	WxSID       string   `xml:"wxsid"`
	WxUIN       string   `xml:"wxuin"`
	PassTicket  string   `xml:"pass_ticket"`
	IsGrayscale int      `xml:"isgrayscale"`
}

type PushLoginURLResp struct {
	Ret  string `json:"ret"`
	Msg  string `json:"msg"`
	UUID string `json:"uuid"`
}

type BaseRequest struct {
	DeviceID string
	Sid      string
	Skey     string
	Uin      string
}

type BaseResponse struct {
	Ret    int
	ErrMsg string
}

type Member struct {
	AttrStatus      int
	DisplayName     string
	KeyWord         string
	MemberStatus    int
	NickName        string
	PYInitial       string
	PYQuanPin       string
	RemarkPYInitial string
	RemarkPYQuanPin string
	Uin             int64
	UserName        string
}

type Contact struct {
	Alias            string
	AppAccountFlag   int
	AttrStatus       int
	ChatRoomId       int64
	City             string
	ContactFlag      int
	DisplayName      string
	EncryChatRoomId  string
	HeadImgUrl       string
	HideInputBarFlag int
	IsOwner          int
	KeyWord          string
	MemberCount      int
	MemberList       []*Member
	NickName         string
	OwnerUin         int64
	PYInitial        string
	PYQuanPin        string
	Province         string
	RemarkName       string
	RemarkPYInitial  string
	RemarkPYQuanPin  string
	Sex              int
	Signature        string
	SnsFlag          int
	StarFriend       int
	Statues          int
	Uin              int64
	UniFriend        int
	UserName         string
	VerifyFlag       int
}

type MPArticle struct {
	Cover  string
	Digest string
	Title  string
	Url    string
}

type MPSubscribeMsg struct {
	MPArticleCount int
	MPArticleList  []*MPArticle
	NickName       string
	Time           int64
	UserName       string
}

type KeyVal struct {
	Key int
	Val int64
}

type SyncKey struct {
	Count int
	List  []KeyVal
}

func (syncKey *SyncKey) String() string {
	buf := bytes.Buffer{}

	for _, kv := range syncKey.List {
		buf.WriteString(fmt.Sprintf("%v_%v|", kv.Key, kv.Val))
	}
	if buf.Len() > 0 {
		buf.Truncate(buf.Len() - 1)
	}
	return buf.String()
}

type User struct {
	AppAccountFlag    int
	ContactFlag       int
	HeadImgFlag       int
	HeadImgUrl        string
	HideInputBarFlag  int
	NickName          string
	PYInitial         string
	PYQuanPin         string
	RemarkName        string
	RemarkPYInitial   string
	RemarkPYQuanPin   string
	Sex               int
	Signature         string
	SnsFlag           int
	StarFriend        int
	Uin               int64
	UserName          string
	VerifyFlag        int
	WebWxPluginSwitch int
}

type WxInitReq struct {
	BaseRequest *BaseRequest
}

type WxInitResp struct {
	BaseResponse        BaseResponse
	ChatSet             string
	ClickReportInterval int64
	ClientVersion       int64
	ContactList         []*Contact
	Count               int
	GrayScale           int
	InviteStartCount    int
	MPSubscribeMsgCount int
	MPSubscribeMsgList  []*MPSubscribeMsg
	SKey                string
	SyncKey             *SyncKey
	User                *User
	SystemTime          int64
}

type WxGetContactResp struct {
	BaseResponse BaseResponse
	MemberCount  int
	MemberList   []*Contact
	Seq          int
}

// TextMessage: text message struct
type TextMessage struct {
	Type         int
	Content      string
	FromUserName string
	ToUserName   string
	LocalID      string
	ClientMsgId  string
}

// ImageMessage
type ImageMessage struct {
	Type         int
	MediaId      string
	Content      string
	FromUserName string
	ToUserName   string
	LocalID      string
	ClientMsgId  string
}

// EmotionMessage: gif/emoji message struct
type EmoticonMessage struct {
	Type         int
	EmojiFlag    int
	MediaId      string
	FromUserName string
	ToUserName   string
	LocalID      string
	ClientMsgId  string
}

type WxSendMsgReq struct {
	BaseRequest *BaseRequest
	Msg         TextMessage
}

type WxSendMsgResp struct {
	BaseResponse BaseResponse
	MsgID        string
	LocalID      string
}

type WxUploadMediaReq struct {
	BaseRequest   *BaseRequest
	UploadType    int
	ClientMediaId int64
	TotalLen      int
	StartPos      int
	DataLen       int
	MediaType     int
	FromUserName  string
	ToUserName    string
	FileMd5       string
}

type WxUploadMediaResp struct {
	BaseResponse      BaseResponse
	MediaId           string
	StarPos           int
	CDNThumbImgHeight int
	CDNThumbImgWidth  int
	EncryFileName     string
}

type WxSendImgMsgReq struct {
	BaseRequest *BaseRequest
	Msg         ImageMessage
	Scene       int
}

type WxSendImgMsgResp struct {
	BaseResponse      BaseResponse
	MediaId           string
	StartPos          int
	CDNThumbImgHeight int
	CDNThumbImgWidth  int
	EncryFileName     string
}

type WxSendEmoticonReq struct {
	BaseRequest *BaseRequest
	Msg         EmoticonMessage
	Scene       int
}

type WxSendEmoticonResp struct {
	BaseResponse BaseResponse
	MsgID        string
	LocalID      string
}

type WxSyncCheckReq struct {
	BaseRequest *BaseRequest
}

type WxStatusNotifyReq struct {
	BaseRequest  *BaseRequest
	ClientMsgId  int64
	Code         int
	FromUserName string
	ToUserName   string
}

type WxStatusNotifyResp struct {
	BaseResponse BaseResponse
	MsgID        string
}

type ContactSearchItem struct {
	UserName        string
	EncryChatRoomId string
}

type WxBatchGetContactReq struct {
	BaseRequest *BaseRequest
	Count       int
	List        []*ContactSearchItem
}

type WxBatchGetContactResp struct {
	BaseResponse BaseResponse
	Count        int
	ContactList  []*Contact
}

type RecommendInfo struct {
	UserName   string
	NickName   string
	QQNum      int
	Provice    string
	City       string
	Content    string
	Signature  string
	Alias      string
	Scene      int
	VerifyFlag int
	AttrStatus int
	Sex        int
	Ticket     string
	OpCode     int
}

type AppInfo struct {
	AppID string
	Type  int
}

type Message struct {
	MsgId                string
	FromUserName         string
	ToUserName           string
	MsgType              int
	Content              string
	Status               int
	ImgStatus            int
	CreateTime           int64
	VoiceLength          int
	PlayLength           int
	FileName             string
	FileSize             string
	MediaId              string
	Url                  string
	AppMsgType           int
	StatusNotifyCode     int
	StatusNotifyUserName string
	RecommendInfo        RecommendInfo
	ForwardFlag          int
	AppInfo              AppInfo
	HasProductId         int
	Ticket               string
	ImgHeight            int
	ImgWidth             int
	SubMsgType           int
	NewMsgId             int64
	OriContent           string
	EncryFileName        string
	IsGroup              bool `json:"-"`
}

type Buff struct {
	Buff string
}

type Profile struct {
	BitFlag           int
	UserName          Buff
	NickName          Buff
	BindUin           int
	BindEmail         Buff
	BindMobile        Buff
	Status            int
	Sex               int
	PersonalCard      int
	Alias             string
	HeadImgUpdateFlag int
	HeadImgUrl        string
	Signature         string
}

type SyncCheckKey SyncKey

type WxSyncReq struct {
	BaseRequest *BaseRequest
	SyncKey     *SyncKey
	RR          int32 `json:"rr"`
}

type WxSyncResp struct {
	BaseResponse           BaseResponse
	AddMsgCount            int
	AddMsgList             []*Message
	ModContactCount        int
	ModContactList         []*Contact
	DelContactCount        int
	DelContactList         []*Contact
	ModChatRoomMemberCount int
	ModChatRoomMemberList  []interface{}
	Profile                Profile
	ContinueFlag           int
	SKey                   string
	SyncKey                *SyncKey
	SyncCheckKey           *SyncCheckKey
}

type VerifyUser struct {
	Value            string
	VerifyUserTicket string
}

type WxVerifyUserReq struct {
	BaseRequest        *BaseRequest
	OpCode             int
	VerifyUserListSize int
	VerifyUserList     []VerifyUser
	VerifyContent      string
	SceneListCount     int
	SceneList          []int
	Skey               string `json:"skey"`
}

type WxVerifyUserResp struct {
	BaseResponse BaseResponse
}
