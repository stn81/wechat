package wxweb

import "net/http"

var specialUserMap map[string]bool

func init() {
	var specialUsers = []string{
		"newsapp",
		"fmessage",
		"filehelper",
		"weibo",
		"qqmail",
		"fmessage",
		"tmessage",
		"qmessage",
		"qqsync",
		"floatbottle",
		"lbsapp",
		"shakeapp",
		"medianote",
		"qqfriend",
		"readerapp",
		"blogapp",
		"facebookapp",
		"masssendapp",
		"meishiapp",
		"feedsapp",
		"voip",
		"blogappweixin",
		"weixin",
		"brandsessionholder",
		"weixinreminder",
		"wxid_novlwrv3lqwv11",
		"gh_22b87fa7cb3c",
		"officialaccounts",
		"notification_messages",
		"wxid_novlwrv3lqwv11",
		"gh_22b87fa7cb3c",
		"wxitil",
		"userexperience_alarm",
		"notification_messages",
	}

	specialUserMap = make(map[string]bool)

	for _, name := range specialUsers {
		specialUserMap[name] = true
	}
}

func IsSpecialUser(name string) bool {
	return specialUserMap[name]
}

func getCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
