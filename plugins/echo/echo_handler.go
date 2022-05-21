package echo

import (
	"context"

	"github.com/stn81/log"
	"github.com/stn81/wechat/wxweb"
)

const Name = "echo_handler"

type echoHandler struct{}

func (h *echoHandler) OnMessage(ctx context.Context, session *wxweb.Session, msg *wxweb.Message) {
	if wxweb.IsSpecialUser(msg.FromUserName) {
		return
	}

	if msg.IsGroup {
		return
	}
	if session.GetUser().UserName != msg.ToUserName || msg.MsgType != wxweb.MsgText {
		return
	}

	if err := session.SendMsg(msg.FromUserName, msg.Content); err != nil {
		log.Error(ctx, "echo msg failed", "from_username", msg.FromUserName, "content", "不在线，请留言", "error", err)
	}
}

func Register(session *wxweb.Session) {
	session.RegisterHandler(Name, wxweb.MsgText, &echoHandler{})
}
