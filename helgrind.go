// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"gitlab.stusta.de/stustanet/helgrind/internal/systemd"
)

func main() {
	var cfg config
	err := cfg.parseFile("/etc/helgrind.json")
	if err != nil {
		log.Fatal(err)
	}

	caCertPool, err := loadCaCert(cfg.CaCert)
	if err != nil {
		log.Fatal(err)
	}

	sign, err := signFuncFromPrivKey(cfg.ServerPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	// http server config
	server := &http.Server{
		Handler: &authHandler{
			Services: cfg.Services,
			Sign:     sign,
		},
		TLSConfig: &tls.Config{
			// security settings
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				// Mozilla recommended ciphers (modern)
				// https://wiki.mozilla.org/Security/Server_Side_TLS
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// ECDHE-ECDSA-AES256-SHA384
				// ECDHE-RSA-AES256-SHA384
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			},
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},

			// client certs
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		},

		// timeouts
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// start serving HTTPS
	if cfg.Listen == "systemd" {
		sockets, err := systemd.Listen()
		if err != nil {
			log.Fatal(err)
		}
		if len(sockets) != 1 {
			log.Fatalf("unexpected number of systemd sockets: expected 1, got %d\n", len(sockets))
		}
		listener, err := sockets[0].Listener()
		if err != nil {
			log.Fatal(err)
		}

		if err = server.ServeTLS(listener, cfg.ServerCertChain, cfg.ServerPrivKey); err != nil {
			log.Fatal(err)
		}

	} else {
		server.Addr = cfg.Listen
		if err = server.ListenAndServeTLS(cfg.ServerCertChain, cfg.ServerPrivKey); err != nil {
			log.Fatal(err)
		}
	}
}
