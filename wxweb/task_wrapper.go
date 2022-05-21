package wxweb

import (
	"context"
	"strings"
)

type TaskWrapper struct {
	handler Handler
	session *Session
	msg     *Message
	ctx     context.Context
}

func WrapTask(ctx context.Context, session *Session, msg *Message, handler Handler) *TaskWrapper {
	return &TaskWrapper{
		handler: handler,
		session: session,
		msg:     msg,
		ctx:     ctx,
	}
}

func (task *TaskWrapper) Run() {
	if strings.Contains(task.msg.FromUserName, "@@") || strings.Contains(task.msg.ToUserName, "@@") {
		task.msg.IsGroup = true
	}
	task.handler.OnMessage(task.ctx, task.session, task.msg)
}
