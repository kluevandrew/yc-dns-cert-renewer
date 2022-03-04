package letsencrypt

import (
	"crypto"
	"github.com/go-acme/lego/registration"
)

type LeUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   crypto.PrivateKey
}

func (u *LeUser) GetEmail() string {
	return u.Email
}

func (u LeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *LeUser) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}
