package wxweb

import "context"

type Handler interface {
	OnMessage(context.Context, *Session, *Message)
}

type HandleFunc func(context.Context, *Session, *Message)

func (f HandleFunc) OnMessage(ctx context.Context, session *Session, msg *Message) {
	f(ctx, session, msg)
}

type HandlerWrapper struct {
	Name    string
	Enabled bool
	Handler Handler
}
