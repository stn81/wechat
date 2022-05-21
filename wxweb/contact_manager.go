package wxweb

import (
	"container/list"
	"sync"
)

type ContactManager struct {
	sync.RWMutex
	contacts *list.List
}

func NewContactManager(contacts []*Contact) *ContactManager {
	m := &ContactManager{
		contacts: list.New(),
	}

	for _, contact := range contacts {
		m.contacts.PushBack(contact)
	}
	return m
}

func (m *ContactManager) AddContact(contact *Contact) {
	m.Lock()
	m.contacts.PushBack(contact)
	m.Unlock()
}

func (m *ContactManager) DelContact(contact *Contact) {
	var next *list.Element

	m.Lock()
	for e := m.contacts.Front(); e != nil; e = next {
		next = e.Next()
		old := e.Value.(*Contact)
		if old.UserName == contact.UserName {
			m.contacts.Remove(e)
			break
		}
	}
	m.Unlock()
}

func (m *ContactManager) ModContact(contact *Contact) {
	var next *list.Element

	m.Lock()
	for e := m.contacts.Front(); e != nil; e = next {
		next = e.Next()
		old := e.Value.(*Contact)
		if old.UserName == contact.UserName {
			m.contacts.Remove(e)
			break
		}
	}
	m.contacts.PushBack(contact)
	m.Unlock()
}
