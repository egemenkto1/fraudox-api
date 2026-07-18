// Package config, uygulama genelindeki tüm ayarlanabilir değerleri
// (timeout'lar, cache TTL'leri, rate limit, port vb.) tek bir yerde
// toplar. Değerler process başlarken Environment Variable'lardan
// okunur; env var set edilmemişse üretimde kanıtlanmış (benchmark
// edilmiş) varsayılan değerler kullanılır.
//
// Neden paket seviyesinde init() ile okunuyor (Load() çağrısı yerine)?
// Çünkü scoring/handler paketlerindeki package-level cache/timeout
// değişkenleri (örn. `var dnsResultCache = cache.New(config.DNSCacheTTL)`)
// kendi paketleri yüklenirken hesaplanıyor. Go'nun paket başlatma sırası
// gereği (import edilen paketler önce initialize edilir) config paketinin
// init()'i, onu import eden tüm paketlerden ÖNCE çalışır; böylece ekstra
// bir "Load()" çağrısı zorunluluğu olmadan doğru değerler garanti edilir.
package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

var (
	// Port, HTTP sunucusunun dinleyeceği port. Env: PORT (default: 8080)
	Port string

	// GlobalRequestTimeout, /api/v1/analyze isteğinin İZİN VERİLEN
	// KESİN üst sınırıdır. Bu süre dolduğunda, henüz tamamlanmamış
	// modüller (DNS/Gravatar/Port taraması) "timed_out" olarak
	// işaretlenir ve elde bulunan sinyallerle Kısmi Puanlama
	// (Partial Score) yapılıp yanıt anında döner.
	// Env: GLOBAL_TIMEOUT_MS (default: 800ms)
	GlobalRequestTimeout time.Duration

	// DNSTimeout, tek bir DNS sorgusu (A/MX/TXT) için üst sınır.
	// Env: DNS_TIMEOUT_MS (default: 3000ms)
	DNSTimeout time.Duration

	// DNSCacheTTL, DNS sonuçlarının önbellekte kalma süresi.
	// Env: DNS_CACHE_TTL_MINUTES (default: 5)
	DNSCacheTTL time.Duration

	// GravatarTimeout, Gravatar HEAD isteği için üst sınır.
	// Env: GRAVATAR_TIMEOUT_MS (default: 4000ms)
	GravatarTimeout time.Duration

	// GravatarCacheTTL, Gravatar sonuçlarının önbellekte kalma süresi.
	// Env: GRAVATAR_CACHE_TTL_MINUTES (default: 60)
	GravatarCacheTTL time.Duration

	// PortScanTimeout, tek bir TCP dial denemesi için üst sınır.
	// Env: PORTSCAN_TIMEOUT_MS (default: 500ms)
	PortScanTimeout time.Duration

	// PortScanCacheTTL, port tarama sonuçlarının önbellekte kalma süresi.
	// Env: PORTSCAN_CACHE_TTL_MINUTES (default: 5)
	PortScanCacheTTL time.Duration

	// RateLimitRPM, IP başına dakikada izin verilen istek sayısı.
	// Env: RATE_LIMIT_RPM (default: 60)
	RateLimitRPM int

	// DisposableUpdateInterval, disposable e-posta veritabanının
	// GitHub'dan kaç saatte bir güncelleneceği.
	// Env: DISPOSABLE_UPDATE_INTERVAL_HOURS (default: 24)
	DisposableUpdateInterval time.Duration
)

func init() {
	Port = getEnvString("PORT", "8080")

	GlobalRequestTimeout = getEnvDurationMs("GLOBAL_TIMEOUT_MS", 800)

	DNSTimeout = getEnvDurationMs("DNS_TIMEOUT_MS", 3000)
	DNSCacheTTL = getEnvDurationMinutes("DNS_CACHE_TTL_MINUTES", 5)

	GravatarTimeout = getEnvDurationMs("GRAVATAR_TIMEOUT_MS", 4000)
	GravatarCacheTTL = getEnvDurationMinutes("GRAVATAR_CACHE_TTL_MINUTES", 60)

	PortScanTimeout = getEnvDurationMs("PORTSCAN_TIMEOUT_MS", 500)
	PortScanCacheTTL = getEnvDurationMinutes("PORTSCAN_CACHE_TTL_MINUTES", 5)

	RateLimitRPM = getEnvInt("RATE_LIMIT_RPM", 60)

	DisposableUpdateInterval = getEnvDurationHours("DISPOSABLE_UPDATE_INTERVAL_HOURS", 24)

	log.Printf(
		"[config] yüklendi: global_timeout=%s dns_timeout=%s dns_cache_ttl=%s "+
			"gravatar_timeout=%s gravatar_cache_ttl=%s portscan_timeout=%s "+
			"portscan_cache_ttl=%s rate_limit_rpm=%d disposable_update_interval=%s port=%s",
		GlobalRequestTimeout, DNSTimeout, DNSCacheTTL,
		GravatarTimeout, GravatarCacheTTL, PortScanTimeout,
		PortScanCacheTTL, RateLimitRPM, DisposableUpdateInterval, Port,
	)
}

func getEnvString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		log.Printf("[config] UYARI: %s='%s' geçersiz, varsayılan (%d) kullanılıyor", key, raw, fallback)
		return fallback
	}
	return v
}

func getEnvDurationMs(key string, fallbackMs int) time.Duration {
	return time.Duration(getEnvInt(key, fallbackMs)) * time.Millisecond
}

func getEnvDurationMinutes(key string, fallbackMinutes int) time.Duration {
	return time.Duration(getEnvInt(key, fallbackMinutes)) * time.Minute
}

func getEnvDurationHours(key string, fallbackHours int) time.Duration {
	return time.Duration(getEnvInt(key, fallbackHours)) * time.Hour
}
