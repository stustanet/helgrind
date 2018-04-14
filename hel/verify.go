// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package hel

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
)

func loadPubKey(filepath string) (key *rsa.PublicKey, err error) {
	bytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("no key in public key file found")
	}
	if block.Type == "PUBLIC KEY" {
		var ikey interface{}
		ikey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			key, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		}
		if key, ok := ikey.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("unsupported private key type")
}

type verifyFunc func(m, sig string) bool

// A Verifier is used to verify and parse the information received from the
// gateway.
type Verifier struct {
	verify verifyFunc
}

// NewVerifier creates a new Verifier using the given public key to verify the
// helgrind headers.
// The public key matching the private key of the helgrind gateway should be used.
func NewVerifier(pubkeyPath string) (verifier Verifier, err error) {
	pubKey, err := loadPubKey(pubkeyPath)
	if err != nil {
		return
	}

	return Verifier{
		verify: func(m, sig string) bool {
			rawsig, _ := hex.DecodeString(sig)
			hashed := sha256.Sum256([]byte(m))
			return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], rawsig) == nil
		},
	}, nil
}

// ParseInfo extracts the information from the helgrind gateway in the given
// headers and verifies the signature for it.
func (v Verifier) ParseInfo(header http.Header) (info Info, valid bool) {
	return parseInfo(v.verify, header)
}
