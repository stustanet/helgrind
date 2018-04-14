// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
		// Headers X-Helgrind-Info and X-Helgrind-Sig are set during auth
	}

	return &httputil.ReverseProxy{
		Director:  director,
		Transport: http.DefaultTransport,
	}
}

func infoHeader(id, name, device string) string {
	return "i=" + url.QueryEscape(id) +
		"&n=" + url.QueryEscape(name) +
		"&d=" + url.QueryEscape(device)
}
