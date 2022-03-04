package letsencrypt

import (
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
)

type Renewer struct {
	User         *LeUser
	client       *lego.Client
	LeURL        *string
	isRegistered bool
}

func NewRenewer(user *LeUser, dnsProvider challenge.Provider, leDirectory string) (*Renewer, error) {
	cfg := lego.NewConfig(user)

	cfg.CADirURL = leDirectory
	cfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	err = client.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		return nil, err
	}

	return &Renewer{
		User:   user,
		client: client,
	}, nil
}

func (r *Renewer) RegisterUser() error {
	// New users will need to register
	reg, err := r.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}

	r.User.Registration = reg

	return nil
}

func (r *Renewer) Renew(domains []string) (*certificate.Resource, error) {
	if !r.isRegistered {
		err := r.RegisterUser()
		if err != nil {
			return nil, err
		}

		r.isRegistered = true
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := r.client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}
