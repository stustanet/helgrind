// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package hel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

type verifyFunc func(m, sig string) bool

// A Verifier is used to verify and parse the information received from the
// gateway.
type Verifier struct {
	cache  cache
	secret []byte
}

func (v *Verifier) verify(m, sig string) bool {
	if len(sig) != 44 {
		return false
	}

	// check cache first
	if actualSig, cached := v.cache.get(m); cached {
		return sig == actualSig
	}

	// verify hashed message
	mac, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}

	hash := hmac.New(sha256.New, v.secret)
	hash.Write([]byte(m))
	actualMac := hash.Sum(nil)

	if hmac.Equal(mac, actualMac) {
		// add to cache if valid
		v.cache.set(m, base64.StdEncoding.EncodeToString(actualMac))
		return true
	}
	return false
}

// NewVerifier creates a new Verifier using the given base64 encoded secret to
// verify the helgrind headers.
func NewVerifier(secret string) (verifier *Verifier, err error) {
	verifier = new(Verifier)

	verifier.secret, err = base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	verifier.cache.reset()
	return
}

// ParseInfo extracts the information from the helgrind gateway in the given
// headers and verifies the signature for it.
func (v Verifier) ParseInfo(header http.Header) (info Info, valid bool) {
	return parseInfo(v.verify, header)
}
