// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

func loadCaCert(filepath string) (*x509.CertPool, error) {
	caCertBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCertBytes); !ok {
		return nil, errors.New("could not add CA cert")
	}
	return caCertPool, nil
}

func sign(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func sendHTTPErr(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

// copied from net/url/url.go
func stripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
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

	// find config for requested service
	host := stripPort(r.Host)
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

	r.Header.Set("X-Helgrind-Info", ci.Header.Info)
	r.Header.Set("X-Helgrind-Sig", ci.Header.Sig)

	service.Proxy.ServeHTTP(w, r)
}
