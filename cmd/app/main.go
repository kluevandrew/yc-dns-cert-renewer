package main

import (
	"context"
	"yc-dns-cert-renewer/internal"
	"yc-dns-cert-renewer/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	app, err := internal.Bootstrap(context.Background(), cfg)
	if err != nil {
		panic(err)
	}

	err = app.Run()
	if err != nil {
		panic(err)
	}
}
