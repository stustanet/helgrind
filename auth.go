package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const (
	caCertPath          = "ca/ca.crt"
	serverCertChainPath = "server/fullchain.pem"
	serverPrivKeyPath   = "server/privkey.pem"
	listenAddr          = ":80"
)

func main() {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	server := &http.Server{
		Addr:    listenAddr,
		Handler: &authHandler{},
		TLSConfig: &tls.Config{
			// Security Settings
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
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

			// Client Certs
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
			//VerifyPeerCertificate: verifyClientCert,
		},

		// Timeouts
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	fmt.Println(server.ListenAndServeTLS(serverCertChainPath, serverPrivKeyPath))
}

// func verifyClientCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
// 	if len(rawCerts) != 1 {
// 		return errors.New("must provide exactly one client cert")
// 	}
// 	log.Println("sha256", sha256.Sum256(rawCerts[0]))
// 	return nil
// }

type authHandler struct{}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// get client certificate
	certs := r.TLS.PeerCertificates
	if len(certs) != 1 {
		http.Error(w, "Must provide exactly one client cert", http.StatusForbidden)
		return
	}
	cert := certs[0]

	// calculate SHA-256 fingerprint
	fp := sha256.Sum256(cert.Raw)

	// fingerprint must be whitelisted for target
	if fp == fp {
		http.Error(w, "Account not active", http.StatusForbidden)
		return
	}

	w.Write([]byte("<proxied content>"))
}
