// Package handler içindeki bu dosya, IP bazlı basit ama etkili bir
// rate limiting (hız sınırlama) mekanizması sağlar. Amaç, API'nin
// özellikle "cache-miss" senaryolarıyla (her seferinde farklı
// email/IP kombinasyonu göndererek gerçek DNS sorgusu + port taraması +
// Gravatar isteği tetikleyen istekler) kötüye kullanılmasını
// (DoS/kaynak tüketimi saldırısı) önlemektir; TTL cache tek başına
// tekrarlanan isteklere karşı korur ama HER ZAMAN FARKLI girdilerle
// gelen bir saldırgana karşı hiçbir koruma sağlamaz.
package handler

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fraud-osint-api/internal/config"
	"fraud-osint-api/internal/models"
)

// rateLimitRequestsPerMinute, bir IP adresinin dakikada yapabileceği
// maksimum istek sayısıdır. Env: RATE_LIMIT_RPM (bkz. internal/config).
var rateLimitRequestsPerMinute = config.RateLimitRPM

// rateLimitBurst, token bucket'ın anlık izin verdiği maksimum istek
// patlamasıdır (burst). 60/dakika oranıyla aynı tutularak "dakikada 60
// istek" kuralı sade ve öngörülebilir tutulur.
var rateLimitBurst = float64(rateLimitRequestsPerMinute)

// rateLimitRefillPerSecond, token bucket'a saniyede eklenen token
// miktarıdır: RPM istek / 60 saniye.
var rateLimitRefillPerSecond = float64(rateLimitRequestsPerMinute) / 60.0

const (
	// visitorIdleTTL, bir IP'den bu süre boyunca hiç istek gelmezse o
	// IP'nin bellekteki kaydının temizleneceği süredir. Bu, çok sayıda
	// farklı IP'den (spoofed veya gerçek) gelen tek seferlik isteklerin
	// belleği sınırsız büyütmesini engeller.
	visitorIdleTTL = 3 * time.Minute

	// cleanupInterval, süresi dolmuş ziyaretçi kayıtlarının ne sıklıkla
	// temizleneceğini belirler.
	cleanupInterval = 1 * time.Minute
)

// visitor, tek bir IP adresine ait token bucket durumunu tutar.
// Kendi kilidi (mutex) sayesinde farklı IP'ler birbirini beklemeden
// eşzamanlı olarak güncellenebilir (global bir kilit yerine IP başına
// ince taneli kilitleme).
type visitor struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// RateLimiter, IP başına bağımsız token bucket'lar tutan, thread-safe
// bir hız sınırlayıcıdır. Klasik "token bucket" algoritması kullanılır:
// her IP'nin bir "kova"sı vardır, kova zamanla sabit hızda dolar
// (refill), her istek kovadan 1 token düşer; kova boşsa istek reddedilir.
// Bu yaklaşım, "dakikada 60 istek" gibi sabit pencere (fixed window)
// sayaçlarının pencere sınırında yaşadığı ani patlama (burst) sorununu
// yumuşatır ve ekstra bellek/CPU maliyeti olmadan sürekli, öngörülebilir
// bir sınırlama sağlar.
type RateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
}

// NewRateLimiter, yeni bir RateLimiter oluşturur ve süresi dolmuş
// kayıtları periyodik temizleyen arka plan goroutine'ini başlatır.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
	}
	go rl.cleanupLoop()
	return rl
}

// getOrCreateVisitor, verilen IP için mevcut visitor'ı döner ya da
// yoksa dolu bir kovayla (burst kadar token) yenisini oluşturur.
// Çoğu istek için sadece okuma kilidi (RLock) yeterlidir; yalnızca yeni
// bir IP ilk kez görüldüğünde yazma kilidine (Lock) geçilir.
func (rl *RateLimiter) getOrCreateVisitor(ip string) *visitor {
	rl.mu.RLock()
	v, exists := rl.visitors[ip]
	rl.mu.RUnlock()
	if exists {
		return v
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	// Çift kontrol (double-checked locking): iki goroutine aynı anda
	// aynı yeni IP için buraya gelmiş olabilir.
	if v, exists := rl.visitors[ip]; exists {
		return v
	}
	v = &visitor{
		tokens:     rateLimitBurst,
		lastRefill: time.Now(),
		lastSeen:   time.Now(),
	}
	rl.visitors[ip] = v
	return v
}

// Allow, verilen IP'nin şu anda bir istek yapmasına izin verilip
// verilmediğini döner. İzin veriliyorsa kovadan 1 token düşürülür.
func (rl *RateLimiter) Allow(ip string) bool {
	v := rl.getOrCreateVisitor(ip)

	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(v.lastRefill).Seconds()
	v.tokens += elapsed * rateLimitRefillPerSecond
	if v.tokens > rateLimitBurst {
		v.tokens = rateLimitBurst
	}
	v.lastRefill = now
	v.lastSeen = now

	if v.tokens < 1.0 {
		return false
	}
	v.tokens -= 1.0
	return true
}

// cleanupLoop, uzun süredir istek göndermemiş IP'lerin kayıtlarını
// bellekten temizleyerek RateLimiter'ın bellek ayak izini sınırlı tutar.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-visitorIdleTTL)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			v.mu.Lock()
			idle := v.lastSeen.Before(cutoff)
			v.mu.Unlock()
			if idle {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware, RateLimiter'ı standart bir http.Handler zincirine bağlar.
// Limiti aşan istemcilere 429 Too Many Requests ve Retry-After header'ı
// döner.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, models.ErrorResponse{
				Error: "istek limiti aşıldı",
				Details: fmt.Sprintf(
					"bu IP adresi için dakikada en fazla %d istek gönderilebilir, lütfen bekleyip tekrar deneyin",
					rateLimitRequestsPerMinute,
				),
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// clientIP, isteğin geldiği IP adresini çıkarır. Öncelik sırası:
//  1. Güvenilir bir ters proxy varsa X-Forwarded-For'un ilk adresi
//     (NOT: bu değer istemci tarafından taklit edilebilir; API doğrudan
//     internete açıksa bu header'a güvenilmemelidir. Üretimde bu API bir
//     reverse proxy/load balancer arkasında koşuyorsa ve o proxy
//     X-Forwarded-For'u güvenilir şekilde set ediyorsa kullanılabilir).
//  2. r.RemoteAddr üzerinden gerçek TCP bağlantı adresi (varsayılan ve
//     en güvenilir kaynak).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For "client, proxy1, proxy2" formatında olabilir;
		// ilk adres orijinal istemcidir.
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Port bilgisi yoksa (nadir), RemoteAddr'ın kendisini adres kabul et.
		return r.RemoteAddr
	}
	return host
}
