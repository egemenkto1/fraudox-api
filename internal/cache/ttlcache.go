// Package cache, kısa ömürlü, thread-safe bir TTL (time-to-live) önbellek
// sağlar. DNS sorguları ve port taramaları gibi I/O-ağırlıklı, sonucu
// kısa sürede değişmeyen işlemlerin tekrar tekrar yapılmasını önlemek
// için kullanılır. Yük testinde (10.000 istek, aynı IP/domain) her
// isteğin baştan DNS/port taraması yapması hem gereksiz gecikme hem de
// hedef sunuculara/DNS sağlayıcılarına karşı istenmeyen bir yük anlamına
// gelir; bu cache bu sorunu ortadan kaldırır.
package cache

import (
	"sync"
	"time"
)

// entry, cache içinde saklanan değeri ve son geçerlilik zamanını tutar.
type entry struct {
	value     interface{}
	expiresAt time.Time
}

// TTLCache, anahtar bazlı, süresi dolan (expiring) değerleri saklayan
// thread-safe bir yapıdır. sync.RWMutex kullanılarak çok sayıda eşzamanlı
// okuma isteği birbirini bloklamadan yürütülebilir.
type TTLCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]entry
}

// New, verilen TTL süresiyle yeni bir cache oluşturur. Ayrıca süresi
// dolmuş kayıtları periyodik olarak temizleyen bir arka plan goroutine'i
// başlatır ki bellek kullanımı zamanla sınırsız büyümesin.
func New(ttl time.Duration) *TTLCache {
	c := &TTLCache{
		ttl: ttl,
		m:   make(map[string]entry),
	}
	go c.janitor()
	return c
}

// Get, verilen anahtara ait değeri döner. Değer yoksa veya süresi
// dolmuşsa (ok=false) döner; süresi dolmuş kayıtlar burada da lazy
// olarak temizlenebilir ama asıl temizlik janitor goroutine'inde yapılır.
func (c *TTLCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, found := c.m[key]
	if !found {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.value, true
}

// Set, verilen anahtar-değer çiftini cache'e yazar ve TTL süresince geçerli kılar.
func (c *TTLCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = entry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// janitor, her TTL/2 sürede bir uyanıp süresi dolmuş kayıtları
// map'ten temizler. Bu, cache'in bellek ayak izini (memory footprint)
// sınırlı tutar; aksi halde her yeni anahtar (örn. her farklı IP)
// map'te sonsuza dek kalırdı.
func (c *TTLCache) janitor() {
	interval := c.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.m {
			if now.After(e.expiresAt) {
				delete(c.m, k)
			}
		}
		c.mu.Unlock()
	}
}
