package scoring

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"fraud-osint-api/internal/cache"
	"fraud-osint-api/internal/config"
	"fraud-osint-api/internal/models"
)

// gravatarHTTPClient, Gravatar isteklerine özel, kısa zaman aşımlı bir
// HTTP istemcisidir. Bağlantı havuzu (connection pooling) transport
// seviyesinde yeniden kullanılarak performans artırılır.
// NOT: Bu Timeout bir güvenlik ağıdır; asıl bağlayıcı sınır,
// AnalyzeHandler'dan geçirilen ctx'in config.GlobalRequestTimeout
// (varsayılan 800ms) ile iptal edilmesidir.
var gravatarHTTPClient = &http.Client{
	Timeout: config.GravatarTimeout,
}

// gravatarCacheTTL, bir e-postanın Gravatar sonucunun ne kadar süre
// önbellekte tutulacağını belirler. Bir kullanıcının profil resmi
// varlığı/yokluğu dakikalar/saatler mertebesinde nadiren değişir; bu
// yüzden DNS/port taramasına göre daha uzun bir TTL (1 saat) güvenle
// kullanılabilir. Yük testlerinde aynı e-postaya tekrar tekrar gelen
// isteklerin her seferinde gerçek bir Gravatar HTTP isteği yapması,
// yanıt süresi kuyruğundaki (p99) en büyük kalan darboğazdı; bu cache
// o darboğazı ortadan kaldırır.
var gravatarCacheTTL = config.GravatarCacheTTL

// gravatarResultCache, emailMD5 -> models.SocialFootprintResult
// eşlemesini tutan, paket seviyesinde paylaşılan thread-safe bir
// cache'tir. Anahtar olarak e-postanın kendisi değil MD5 hash'i
// kullanılır; böylece cache içeriği bir e-postayı doğrudan saklamaz.
var gravatarResultCache = cache.New(gravatarCacheTTL)

// AnalyzeSocialFootprint, e-postayı MD5 ile hash'leyip Gravatar'ın
// "d=404" parametresiyle profil resminin var olup olmadığını kontrol eder.
// Gravatar API'si tamamen ücretsiz ve kimlik doğrulama gerektirmez.
// Sonuç, gravatarCacheTTL süresince MD5 hash anahtarıyla önbelleğe alınır.
func AnalyzeSocialFootprint(ctx context.Context, email string) models.SocialFootprintResult {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	hash := md5.Sum([]byte(normalizedEmail))
	hashHex := hex.EncodeToString(hash[:])

	// --- Önbellek kontrolü ---
	if cached, ok := gravatarResultCache.Get(hashHex); ok {
		if cachedResult, ok := cached.(models.SocialFootprintResult); ok {
			cachedResult.FromCache = true
			return cachedResult
		}
	}

	result := models.SocialFootprintResult{
		EmailMD5: hashHex,
	}

	// d=404 parametresi, profil resmi bulunmadığında Gravatar'ın
	// varsayılan (placeholder) görsel yerine gerçek bir 404 HTTP durum
	// kodu döndürmesini sağlar; bu da varlık/yokluk kontrolünü kesinleştirir.
	url := fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=404", hashHex)
	result.GravatarURL = url

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		result.CheckError = err.Error()
		// İstek oluşturulamadıysa (programatik hata) cache'lemiyoruz;
		// bu bir ağ durumu değil, tekrar denense de aynı sonuç çıkar
		// ama gelecekte kod değişirse yanlış pozitif tutmamak için
		// yine de önbelleğe yazmıyoruz.
		return result
	}

	resp, err := gravatarHTTPClient.Do(req)
	if err != nil {
		// Ağ hatası (offline/erişilemez) durumunda nötr kalıyoruz; bu bir
		// risk artışı sebebi değildir çünkü Gravatar servisinin kendisi
		// geçici olarak erişilemez olabilir. ÖNEMLİ: geçici ağ hatalarını
		// KASITLI OLARAK önbelleğe yazmıyoruz; aksi halde geçici bir kesinti,
		// 1 saat boyunca yanlış "check_error" sonucunun tekrarlanmasına
		// sebep olurdu.
		result.CheckError = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.HTTPStatusCode = resp.StatusCode

	if resp.StatusCode == http.StatusOK {
		result.GravatarExists = true
		// Aktif ve doğrulanabilir bir sosyal profil, meşru kullanıcı
		// olasılığını artırdığı için risk puanını düşürür.
		result.RiskContribution = -15
	} else if resp.StatusCode == http.StatusNotFound {
		result.GravatarExists = false
		// Profil resmi yoksa risk nötr kalır (hafif bir artış eklenebilir
		// ancak bu tek başına güçlü bir sinyal olmadığından minimal tutulur).
		result.RiskContribution = 5
	}
	// Not: 200/404 dışındaki durum kodları (örn. 403 - Gravatar'ın bot
	// koruması/rate-limit'i tetiklenmiş olabilir) risk puanına dahil
	// edilmez ve GravatarExists=false, RiskContribution=0 kalır; bu
	// belirsiz bir sinyali riskmiş gibi göstermemek için bilinçli bir
	// tercihtir. Böyle belirsiz sonuçlar da önbelleğe YAZILMAZ ki
	// geçici bir rate-limit durumu 1 saat boyunca tekrarlanmasın.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		gravatarResultCache.Set(hashHex, result)
	}

	return result
}
