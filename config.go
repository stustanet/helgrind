// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
)

// struct used to parse the config from the JSON file
type jsonConfig struct {
	Listen          string
	CaCert          string
	ServerCertChain string
	ServerPrivKey   string
	Services        map[string]struct {
		Enabled bool
		Host    string
		Target  string
		Secret  string
		Users   map[string]struct {
			Enabled bool
			Name    string
			Devices []struct {
				Enabled bool
				Name    string
				Sha256  string
			}
		}
	}
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func parseSha256(v string) (fp [32]byte, err error) {
	// increment per fp byte
	inc := 0

	switch len(v) {
	case 64:
		// hex encoding without separator
		inc = 2
	case 95:
		// hex encoding with 1 byte separator
		inc = 3
	}

	if inc > 0 {
		pos := 0
		for i := range fp {
			a, ok1 := fromHexChar(v[pos])
			b, ok2 := fromHexChar(v[pos+1])

			// abort if we found an illegal char
			if !ok1 || !ok2 {
				break
			}

			fp[i] = (a << 4) | b
			pos += inc
		}

		// if we processed all chars, then the fp is a valid hash
		if pos == inc*32 {
			return fp, nil
		}
	}

	err = fmt.Errorf("unknown SHA-256 format: %s", v)
	return
}

type user struct {
	ID   string
	Name string
}

type certInfo struct {
	Device string
	User   *user
	Header struct {
		Info string
		Sig  string
	}
}

type service struct {
	Secret     []byte
	ValidCerts map[[32]byte]certInfo
	Proxy      *httputil.ReverseProxy
}

type config struct {
	Listen          string
	CaCert          string
	ServerCertChain string
	ServerPrivKey   string
	Services        map[string]service
}

func (cfg *config) parseFile(filepath string) (err error) {
	// parse values from JSON config file
	var f *os.File
	if f, err = os.Open(filepath); err != nil {
		return
	}
	var jc jsonConfig
	err = json.NewDecoder(f).Decode(&jc)
	f.Close()
	if err != nil {
		return
	}

	// build config from new values
	services := make(map[string]service, len(jc.Services))
	for name, js := range jc.Services {
		if !js.Enabled {
			continue
		}

		target, err := url.ParseRequestURI(js.Target)
		if err != nil {
			return err
		}

		secret, err := base64.StdEncoding.DecodeString(js.Secret)
		if err != nil {
			return err
		}

		s := service{
			Secret:     secret,
			ValidCerts: make(map[[32]byte]certInfo),
			Proxy:      newReverseProxy(target),
		}

		for id, ju := range js.Users {
			if !ju.Enabled {
				continue
			}

			u := user{
				ID:   id,
				Name: ju.Name,
			}

			for _, jd := range ju.Devices {
				if !jd.Enabled {
					continue
				}

				fp, err := parseSha256(jd.Sha256)
				if err != nil {
					return err
				}

				s.ValidCerts[fp] = certInfo{
					Device: jd.Name,
					User:   &u,
				}
			}
		}
		services[name] = s
	}

	// overwrite when we know that the new config doesn't contain any errors
	cfg.Listen = jc.Listen
	cfg.CaCert = jc.CaCert
	cfg.ServerCertChain = jc.ServerCertChain
	cfg.ServerPrivKey = jc.ServerPrivKey
	cfg.Services = services
	return
}

func (cfg *config) precomputeAuthHeaders() error {
	for _, s := range cfg.Services {
		for fp, ci := range s.ValidCerts {
			info := infoHeader(ci.User.ID, ci.User.Name, ci.Device)
			ci.Header.Info = info
			ci.Header.Sig = sign(s.Secret, []byte(info))
			s.ValidCerts[fp] = ci
		}
	}
	return nil
}
