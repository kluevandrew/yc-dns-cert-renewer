package internal

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"os"
	"time"
	"yc-dns-cert-renewer/internal/config"
	"yc-dns-cert-renewer/internal/k8s"
	"yc-dns-cert-renewer/internal/letsencrypt"
	"yc-dns-cert-renewer/internal/yandex"
)

type App struct {
	Period       time.Duration
	DNSProvider  *yandex.DNSProvider
	Renewer      *letsencrypt.Renewer
	Group        *errgroup.Group
	Context      context.Context
	K8S          *k8s.Client
	Certificates config.Certificates
	ArchivePath  string
}

func (app *App) Run() error {
	ticker := time.NewTicker(1 * time.Hour)

	err := app.Tick()
	if err != nil {
		return err
	}

	app.Group.Go(func() error {
		for range ticker.C {
			err := app.Tick()
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err := app.Group.Wait(); err != nil {
		return err
	}

	return nil
}

func (app *App) Tick() error {
	for _, cert := range app.Certificates {
		firstNs := cert.Namespaces[0]
		secret, err := app.K8S.GetSecret(app.Context, firstNs, cert.SecretName)
		renew := false

		if err != nil {
			fmt.Printf("%s cert is not exists [ns]%s\nError: %s", cert.SecretName, firstNs, err.Error())

			renew = true
		} else {
			sslCert, err := app.ParseCert(secret.Data["tls.crt"])
			if err != nil {
				return err
			}
			if sslCert.NotAfter.Before(time.Now().Add(7 * 24 * time.Hour)) {
				fmt.Printf("Shoud update cert %s it expires at %s.\n", cert.SecretName, sslCert.NotAfter)

				renew = true
			} else {
				fmt.Printf("%s cert is ok it expires at %s [ns]%s.\n", cert.SecretName, sslCert.NotAfter, firstNs)

				for _, ns := range cert.Namespaces {
					if ns != firstNs {
						err := app.K8S.CreateOrUpdateSecret(app.Context, ns, cert.SecretName, secret.Data["tls.crt"], secret.Data["tls.key"])
						if err != nil {
							return err
						}
					}
				}
			}
		}

		if renew {
			certificates, err := app.Renewer.Renew(cert.Domains)
			if err != nil {
				return err
			}

			err = app.saveCertificates(certificates)
			if err != nil {
				return err
			}

			for _, ns := range cert.Namespaces {
				err := app.K8S.CreateOrUpdateSecret(app.Context, ns, cert.SecretName, certificates.Certificate, certificates.PrivateKey)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (app *App) ParseCert(bytes []byte) (*x509.Certificate, error) {
	certs, err := certcrypto.ParsePEMBundle(bytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

func (app *App) saveCertificates(certificates *certificate.Resource) error {
	path := fmt.Sprintf("%s/%s/%d", app.ArchivePath, certificates.Domain, time.Now().Unix())

	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path+"/privkey.pem", certificates.PrivateKey, 0777)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path+"/fullchain.pem", certificates.Certificate, 0777)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path+"/chain.pem", certificates.IssuerCertificate, 0777)
	if err != nil {
		return err
	}

	jsonString, err := json.Marshal(certificates)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path+"/info.json", jsonString, 0777)
	if err != nil {
		return err
	}

	return nil
}
