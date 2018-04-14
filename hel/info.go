// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package hel

import (
	"net/http"
	"net/url"
	"strings"
)

// Info is information transmitted by helgrind via the request headers.
type Info struct {
	ID     string
	Name   string
	Device string
}

func parseInfo(verify verifyFunc, header http.Header) (info Info, valid bool) {
	// get helgrind headers
	infoHeader := header.Get("X-Helgrind-Info")
	sigHeader := header.Get("X-Helgrind-Sig")

	// verify header signature
	if valid = verify(infoHeader, sigHeader); !valid {
		return
	}

	// parse info from header
	vars := strings.Split(infoHeader, "&")
	for _, v := range vars {
		switch v[0:2] {
		case "i=":
			info.ID, _ = url.QueryUnescape(v[2:])
		case "n=":
			info.Name, _ = url.QueryUnescape(v[2:])
		case "d=":
			info.Device, _ = url.QueryUnescape(v[2:])
		}
	}
	return
}
