// Copyright 2018 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

package hel

import (
	"sync"
)

type cache struct {
	m map[string]string
	l sync.RWMutex
}

func (c *cache) reset() {
	c.l.Lock()
	c.m = make(map[string]string)
	c.l.Unlock()
}

func (c *cache) get(key string) (value string, ok bool) {
	c.l.RLock()
	value, ok = c.m[key]
	c.l.RUnlock()
	return
}

func (c *cache) set(key, value string) {
	c.l.Lock()
	c.m[key] = value
	c.l.Unlock()
}
