package internal

import (
	"context"
	"golang.org/x/sync/errgroup"
	"yc-dns-cert-renewer/internal/config"
	"yc-dns-cert-renewer/internal/k8s"
	"yc-dns-cert-renewer/internal/letsencrypt"
	"yc-dns-cert-renewer/internal/yandex"
)

func Bootstrap(ctx context.Context, cfg *config.Config) (*App, error) {
	group, egCtx := errgroup.WithContext(ctx)

	dnsProvider, err := yandex.NewDNSProvider(egCtx, cfg.YandexCredentials, cfg.YandexFolderID)
	if err != nil {
		return nil, err
	}

	user := &letsencrypt.LeUser{
		Email:      cfg.LeEmail,
		PrivateKey: cfg.LePrivateKey,
	}

	renewer, err := letsencrypt.NewRenewer(user, dnsProvider, cfg.LeDirectory)
	if err != nil {
		return nil, err
	}

	k8sClient, err := k8s.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	app := &App{
		Group:        group,
		DNSProvider:  dnsProvider,
		Renewer:      renewer,
		Context:      egCtx,
		K8S:          k8sClient,
		Certificates: cfg.Certificates,
		ArchivePath:  cfg.ArchivePath,
	}

	return app, nil
}
