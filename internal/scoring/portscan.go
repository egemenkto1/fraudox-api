package scoring

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"fraud-osint-api/internal/cache"
	"fraud-osint-api/internal/config"
	"fraud-osint-api/internal/models"
)

// proxyPortTimeout, her bir TCP bağlantı denemesi için maksimum bekleme
// süresidir. Düşük tutularak taramanın genel API yanıt süresini
// olumsuz etkilememesi sağlanır.
var proxyPortTimeout = config.PortScanTimeout

// portScanCacheTTL, aynı IP için port tarama sonucunun ne kadar süre
// önbellekte tutulacağını belirler. Aynı IP'ye art arda gelen yoğun
// istek trafiğinde (örn. yük testi, tekrarlanan sorgular) her seferinde
// gerçek bir TCP taraması yapmak hem gecikme hem de hedefe karşı
// gereksiz bir ağ yükü anlamına gelir.
var portScanCacheTTL = config.PortScanCacheTTL

// portScanResultCache, ip -> models.PortScanResult eşlemesini tutan
// paket seviyesinde paylaşılan, thread-safe bir cache'tir.
var portScanResultCache = cache.New(portScanCacheTTL)

// suspiciousPorts, yaygın olarak proxy/VPN/SOCKS servisleri tarafından
// kullanılan port numaraları ve okunabilirlik için servis ipuçlarıdır.
var suspiciousPorts = map[int]string{
	1080: "SOCKS Proxy",
	3128: "Squid HTTP Proxy",
	8080: "HTTP Proxy / Alt-HTTP",
	1194: "OpenVPN",
}

// AnalyzePortScan, hedef IP adresindeki bilinen proxy/VPN portlarını
// eşzamanlı goroutine'ler kullanarak tarar. Her port bağımsız bir
// goroutine'de, kısa bir zaman aşımıyla (dial timeout) test edilir;
// böylece 4 port taraması, sıralı taramaya göre en yavaş portun
// süresine yakın bir sürede tamamlanır.
//
// ctx, AnalyzeHandler'ın strict global timeout'unu (varsayılan 800ms)
// taşır: her port denemesi hem kendi proxyPortTimeout'una hem de bu
// ctx'e bağlıdır (hangisi önce dolarsa). Bu sayede, çağıran taraf
// select/ctx.Done() ile "partial scoring" moduna geçtiğinde bu
// goroutine'ler de gereksiz yere TCP el sıkışması denemeye devam
// etmez, kaynaklar (soket/fd) hızla serbest kalır.
func AnalyzePortScan(ctx context.Context, ip string) models.PortScanResult {
	start := time.Now()
	result := models.PortScanResult{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		result.ValidIP = false
		result.RiskContribution = 0
		return result
	}
	result.ValidIP = true

	// --- Önbellek kontrolü ---
	// Not: handler katmanı zaten geçersiz IP'leri 400 ile reddettiği için
	// buraya normalde yalnızca geçerli IP'ler ulaşır; yine de yukarıdaki
	// ParseIP kontrolü savunma amaçlı (defense-in-depth) korunur.
	if cached, ok := portScanResultCache.Get(ip); ok {
		if cachedResult, ok := cached.(models.PortScanResult); ok {
			cachedResult.FromCache = true
			return cachedResult
		}
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		ports  = make([]models.OpenPort, 0, len(suspiciousPorts))
		dialer = net.Dialer{}
	)

	for port, hint := range suspiciousPorts {
		wg.Add(1)
		go func(port int, hint string) {
			defer wg.Done()

			// Her dial denemesi, HEM proxyPortTimeout (soket seviyesinde
			// kısa bir üst sınır) HEM DE üst ctx (handler'ın strict
			// global timeout'u) ile sınırlıdır; hangisi önce dolarsa
			// bağlantı denemesi orada kesilir.
			dialCtx, cancel := context.WithTimeout(ctx, proxyPortTimeout)
			defer cancel()

			address := fmt.Sprintf("%s:%d", ip, port)
			conn, err := dialer.DialContext(dialCtx, "tcp", address)

			isOpen := false
			if err == nil {
				isOpen = true
				_ = conn.Close()
			}

			mu.Lock()
			ports = append(ports, models.OpenPort{
				Port:        port,
				IsOpen:      isOpen,
				ServiceHint: hint,
			})
			mu.Unlock()
		}(port, hint)
	}

	wg.Wait()
	result.ScannedPorts = ports

	anyOpen := false
	for _, p := range ports {
		if p.IsOpen {
			anyOpen = true
			break
		}
	}
	result.AnyProxyPortOpen = anyOpen

	if anyOpen {
		// Bilinen bir proxy/VPN portunun açık olması, IP'nin trafiği
		// gizliyor olabileceğine dair güçlü bir sinyaldir -> yüksek risk.
		result.RiskContribution = 35
	}

	result.ScanDurationMs = time.Since(start).Milliseconds()

	// Sonucu önbelleğe yaz (5 dakika geçerli). FromCache=false olarak
	// saklanır; sonraki bir Get çağrısında true'ya çevrilir.
	portScanResultCache.Set(ip, result)

	return result
}
