package autoaccept

import (
	"context"

	"github.com/stn81/wechat/wxweb"
)

const Name = "autoaccept_handler"

type autoAcceptHandler struct{}

func (h *autoAccept) OnMessage(ctx context.Context, session *wxweb.Session, msg *wxweb.Message) {
}

func Register(session *wxweb.Session) {
	session.RegisterHandler(Name, wxweb.MsgText, &autoAcceptHandler{})
}
