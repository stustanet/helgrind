// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

func loadPrivKey(filepath string) (key *rsa.PrivateKey, err error) {
	bytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("no key in private key file found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return
	case "PRIVATE KEY":
		var ikey interface{}
		ikey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		}
		if key, ok := ikey.(*rsa.PrivateKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("unsupported private key type")
}

func main() {
	var cfg config
	err := cfg.parseFile("etc/helgrind.json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cfg)

	caCertBytes, err := ioutil.ReadFile(cfg.CaCert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertBytes)

	privKey, err := loadPrivKey(cfg.ServerPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	// sign := func(m string) string {
	// 	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, 0, []byte(m))
	// 	return hex.EncodeToString(sig)
	// }
	rng := rand.Reader
	sign := func(m string) string {
		hashed := sha256.Sum256([]byte(m))
		sig, _ := rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])
		return hex.EncodeToString(sig)
	}

	// http server config
	server := &http.Server{
		Addr: cfg.Listen,
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
	if err = server.ListenAndServeTLS(cfg.ServerCertChain, cfg.ServerPrivKey); err != nil {
		log.Fatal(err)
	}
}

func sendHTTPErr(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

type authHandler struct {
	Services map[string]service
	Sign     func(m string) string
}

func (ah *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// get client certificate
	certs := r.TLS.PeerCertificates
	if len(certs) != 1 {
		http.Error(w, "Must provide exactly one client cert", http.StatusForbidden)
		return
	}
	cert := certs[0]

	// find config for requested service
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

	info := infoHeader(ci.User.ID, ci.User.Name, ci.Device)
	sig := ah.Sign(info)
	r.Header.Set("X-Helgrind-Info", info)
	r.Header.Set("X-Helgrind-Sig", sig)

	service.Proxy.ServeHTTP(w, r)
}
