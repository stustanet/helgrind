// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net"
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

func signFuncFromPrivKey(filepath string) (func(m string) string, error) {
	privKey, err := loadPrivKey(filepath)
	if err != nil {
		return nil, err
	}
	// sign := func(m string) string {
	//  sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, 0, []byte(m))
	//  return hex.EncodeToString(sig)
	// }
	rng := rand.Reader
	sign := func(m string) string {
		hashed := sha256.Sum256([]byte(m))
		sig, _ := rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])
		return hex.EncodeToString(sig)
	}
	return sign, nil
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

	info := infoHeader(ci.User.ID, ci.User.Name, ci.Device)
	sig := ah.Sign(info)
	r.Header.Set("X-Helgrind-Info", info)
	r.Header.Set("X-Helgrind-Sig", sig)

	service.Proxy.ServeHTTP(w, r)
}
