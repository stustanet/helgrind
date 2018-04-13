// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
)

type config struct {
	Listen          string
	CaCert          string
	ServerCertChain string
	ServerPrivKey   string
	Services        map[string]struct {
		Enabled bool
		Host    string
		Target  string
		Users   map[string]struct {
			Enabled bool
			Name    string
			Devices []struct {
				Enabled bool
				Sha256  string
			}
		}
	}
}

func loadConfig() (cfg config, err error) {
	var f *os.File
	if f, err = os.Open("etc/helgrind.json"); err != nil {
		panic(err)
		return
	}

	err = json.NewDecoder(f).Decode(&cfg)
	f.Close()
	return
}
