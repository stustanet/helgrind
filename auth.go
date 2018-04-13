// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	var cfg config
	err := cfg.parseFile("etc/helgrind.json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cfg)

	caCert, err := ioutil.ReadFile(cfg.CaCert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// http server config
	server := &http.Server{
		Addr:    cfg.Listen,
		Handler: &authHandler{Services: cfg.Services},
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
	if err = server.ListenAndServeTLS(cfg.ServerCertChain, cfg.ServerPrivKey); err != nil {
		log.Fatal(err)
	}
}

func sendHTTPErr(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

type authHandler struct {
	Services map[string]service
}

func (ah *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// get client certificate
	certs := r.TLS.PeerCertificates
	if len(certs) != 1 {
		http.Error(w, "Must provide exactly one client cert", http.StatusForbidden)
		return
	}
	cert := certs[0]

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		sendHTTPErr(w, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	service, ok := ah.Services[host]
	if !ok {
		sendHTTPErr(w, http.StatusForbidden)
		return
	}

	// calculate SHA-256 fingerprint
	fp := sha256.Sum256(cert.Raw)

	// fingerprint must be whitelisted for target
	ci, ok := service.ValidCerts[fp]
	if !ok {
		sendHTTPErr(w, http.StatusForbidden)
		return
	}

	fmt.Fprintln(w, "Hello", ci.User.Name, "(", ci.User.ID, ") on Device", ci.Device)
}
