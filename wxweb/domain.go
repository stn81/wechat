package wxweb

import "strings"

type Domain struct {
	Index string
	File  string
	Push  string
}

type DomainList []*Domain

func (dl DomainList) GetDomain(index string) *Domain {
	for _, domain := range dl {
		if strings.Contains(index, domain.Index) {
			return domain
		}
	}
	return nil
}

var DefaultDomainList = DomainList{
	{"wx2.qq.com", "file.wx2.qq.com", "webpush.wx2.qq.com"},
	{"wx8.qq.com", "file.wx8.qq.com", "webpush.wx8.qq.com"},
	{"qq.com", "file.wx.qq.com", "webpush.wx.qq.com"},
	{"web2.wechat.com", "file.web2.wechat.com", "webpush.web2.wechat.com"},
	{"wechat.com", "file.web.wechat.com", "webpush.web.wechat.com"},
}
