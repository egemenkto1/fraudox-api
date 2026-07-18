// Package handler, HTTP katmanını (routing, request/response,
// orkestrasyon) içerir. İş mantığı (scoring, disposable) alt paketlerden
// çağrılır; bu paket sadece bunları bir araya getirir.
package handler

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"fraud-osint-api/internal/config"
	"fraud-osint-api/internal/disposable"
	"fraud-osint-api/internal/models"
	"fraud-osint-api/internal/scoring"
)

// requestTimeout, tek bir /analyze isteğinin tüm alt modüller dahil
// tamamlanması için tanınan KESİN (strict) üst sınırdır. Cache-miss
// senaryosunda DNS/Gravatar timeout'ları p99'u 4 saniyeye kadar
// çıkarabiliyordu; bu değer artık config'ten (varsayılan 800ms) okunur
// ve süre dolduğunda henüz bitmemiş modüller "timed_out" işaretlenip
// Kısmi Puanlama (Partial Scoring) ile anında yanıt dönülür (bkz.
// ServeHTTP içindeki select/ctx.Done() mantığı).
var requestTimeout = config.GlobalRequestTimeout

// AnalyzeHandler, POST /api/v1/analyze uç noktasının bağımlılıklarını
// (disposable email store gibi) taşıyan yapıdır. Bağımlılık enjeksiyonu
// (dependency injection) sayesinde test edilebilirlik artar.
type AnalyzeHandler struct {
	DisposableStore *disposable.Store
}

// NewAnalyzeHandler, verilen bağımlılıklarla yeni bir AnalyzeHandler oluşturur.
func NewAnalyzeHandler(store *disposable.Store) *AnalyzeHandler {
	return &AnalyzeHandler{DisposableStore: store}
}

// ServeHTTP, isteği doğrular, tüm analiz modüllerini paralel olarak
// çalıştırır, sonuçları birleştirir ve nihai JSON yanıtını yazar.
func (h *AnalyzeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "yalnızca POST metodu desteklenir", "")
		return
	}

	var req models.AnalyzeRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "geçersiz JSON gövdesi", err.Error())
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.IP = strings.TrimSpace(req.IP)

	if req.Email == "" || req.IP == "" {
		writeError(w, http.StatusBadRequest, "'email' ve 'ip' alanları zorunludur", "")
		return
	}

	addr, err := mail.ParseAddress(req.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "geçersiz e-posta formatı", err.Error())
		return
	}

	// IP adresi burada, herhangi bir modüle (özellikle port taramasına)
	// ulaşmadan ÖNCE doğrulanır. Öncesinde geçersiz bir IP (örn.
	// "999.999.999.999") port tarama modülüne kadar sızıyor ve orada
	// sessizce "valid_ip: false" olarak işaretlenip 200 OK ile
	// dönülüyordu; bu, istemci hatasını (400) sunucu tarafında maskeleyen
	// yanlış bir davranıştı. Artık istek gövdesi geçerliliği tek bir
	// yerde (handler girişinde) net şekilde reddediliyor.
	if net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "geçersiz IP adresi formatı", req.IP)
		return
	}

	domain := extractDomain(addr.Address)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "e-posta alan adı çıkarılamadı", "")
		return
	}

	// ctx, bu isteğin tüm alt modüller dahil tabi olduğu KESİN üst
	// sınırdır (config.GlobalRequestTimeout, varsayılan 800ms). Süre
	// dolduğunda henüz bitmemiş modüller iptal edilir ve aşağıdaki
	// select döngüsü Kısmi Puanlama moduna geçer.
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	// --- Tüm bağımsız modülleri eşzamanlı (concurrent) olarak çalıştır ---
	// Typo-squat ve disposable kontrolleri CPU-bound/O(1) olduğundan
	// senkron çağrılabilir; DNS, Gravatar ve port taraması I/O-bound
	// olduğundan goroutine ile paralelleştiriliyor.
	//
	// ÖNEMLİ (data race önleme): her goroutine sonucunu DOĞRUDAN paylaşılan
	// bir değişkene yazmıyor, kendine ait buffered (kapasiteli) bir
	// kanala gönderiyor. Ana goroutine bu kanallardan select ile okuyor;
	// böylece "ctx timeout olduğu için ana goroutine sonucu erken okumaya
	// başladı ama arka plan goroutine'i hâlâ değişkene yazıyordu" tarzı
	// bir race koşulu yapısal olarak imkansız hale geliyor (goroutine
	// sızıntısı da yaşanmaz: cancel edilen ctx sayesinde HTTP istekleri
	// ve dial'lar kısa sürede kendiliğinden sonlanır, kanal ise buffered
	// olduğu için gönderen goroutine asla bloke kalmaz).
	dnsCh := make(chan models.DNSResult, 1)
	socialCh := make(chan models.SocialFootprintResult, 1)
	portCh := make(chan models.PortScanResult, 1)

	go func() {
		dnsCh <- scoring.AnalyzeDNS(ctx, domain)
	}()

	go func() {
		socialCh <- scoring.AnalyzeSocialFootprint(ctx, addr.Address)
	}()

	go func() {
		portCh <- scoring.AnalyzePortScan(ctx, req.IP)
	}()

	// Hızlı, senkron modüller ana goroutine'de hesaplanır.
	typoResult := scoring.AnalyzeTyposquat(domain)

	isDisposable := h.DisposableStore.IsDisposable(domain)
	disposableResult := models.DisposableResult{
		Domain:             domain,
		IsDisposable:       isDisposable,
		DatabaseSize:       h.DisposableStore.Size(),
		DatabaseLastUpdate: h.DisposableStore.LastUpdated(),
	}
	if isDisposable {
		disposableResult.RiskContribution = 40
	}

	// --- Strict Global Timeout & Partial Scoring ---
	// Üç I/O-bound modülün de bitmesini BEKLEMEK YERİNE, hangisi önce
	// gerçekleşirse: (a) bir modül sonucunu gönderir, (b) ctx süresi
	// dolar. ctx dolduğunda henüz gelmemiş modüller "timed_out: true"
	// ve nötr (0) risk katkısıyla işaretlenir; elde bulunan sinyallerle
	// hemen Kısmi Puanlama yapılıp yanıt döner. Alınan bir kanal `nil`
	// yapılır ki select bir daha o case'i seçmesin (nil kanal sonsuza
	// dek bloklar, bu Go'da idiomatik "kapatma" tekniğidir) ve tekrar
	// aynı sonucun iki kez işlenmesi engellenir.
	var (
		dnsResult      models.DNSResult
		socialResult   models.SocialFootprintResult
		portScanResult models.PortScanResult
		partial        bool
		skipped        []string
	)

	remaining := 3
waitLoop:
	for remaining > 0 {
		select {
		case dnsResult = <-dnsCh:
			dnsCh = nil
			remaining--
		case socialResult = <-socialCh:
			socialCh = nil
			remaining--
		case portScanResult = <-portCh:
			portCh = nil
			remaining--
		case <-ctx.Done():
			partial = true
			break waitLoop
		}
	}

	if partial {
		if dnsCh != nil {
			dnsResult = models.DNSResult{Domain: domain, TimedOut: true}
			skipped = append(skipped, "dns")
		}
		if socialCh != nil {
			hash := gravatarHashOrEmpty(addr.Address)
			socialResult = models.SocialFootprintResult{EmailMD5: hash, TimedOut: true}
			skipped = append(skipped, "social_footprint")
		}
		if portCh != nil {
			portScanResult = models.PortScanResult{IP: req.IP, ValidIP: true, TimedOut: true}
			skipped = append(skipped, "port_scan")
		}
	}

	// --- Nihai risk skorunu hesapla ve karar (verdict) ver ---
	// Not: timeout'a uğrayan modüllerin RiskContribution'ı 0'dır (nötr);
	// eksik bir sinyal asla riskmiş gibi yorumlanmaz. Bu, "yetişemeyen
	// modülü cezalandırma" yerine "yetişen sinyallerle karar ver"
	// felsefesinin doğrudan uygulamasıdır.
	riskScore := computeRiskScore(typoResult, dnsResult, socialResult, portScanResult, disposableResult)
	verdict := computeVerdict(riskScore)

	response := models.AnalyzeResponse{
		Email:            addr.Address,
		IP:               req.IP,
		RiskScore:        riskScore,
		Verdict:          verdict,
		TypoSquat:        typoResult,
		DNS:              dnsResult,
		SocialFootprint:  socialResult,
		PortScan:         portScanResult,
		Disposable:       disposableResult,
		PartialResult:    partial,
		SkippedModules:   skipped,
		ProcessingTimeMs: time.Since(start).Milliseconds(),
		Timestamp:        time.Now().UTC(),
	}

	writeJSON(w, http.StatusOK, response)
}

// computeRiskScore, her modülün risk katkısını toplayıp 0-100 aralığına
// sıkıştırır (clamp). Ağırlıklar, her modülün göreceli önemine göre
// modüllerin kendi içinde belirlenmiştir (bkz. ilgili dosyalar).
func computeRiskScore(
	typo models.TypoSquatResult,
	dns models.DNSResult,
	social models.SocialFootprintResult,
	port models.PortScanResult,
	disp models.DisposableResult,
) int {
	total := typo.RiskContribution +
		dns.RiskContribution +
		social.RiskContribution +
		port.RiskContribution +
		disp.RiskContribution

	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}
	return total
}

// computeVerdict, nihai risk skorunu üç kategorili bir iş kararına eşler.
func computeVerdict(score int) models.Verdict {
	switch {
	case score >= 70:
		return models.VerdictBlock
	case score >= 35:
		return models.VerdictReview
	default:
		return models.VerdictAllow
	}
}

// gravatarHashOrEmpty, Partial Scoring sırasında bir Gravatar isteği
// timeout'a uğradığında bile yanıtta tutarlı bir email_md5 alanı
// gösterebilmek için kullanılır (scoring.AnalyzeSocialFootprint ile
// aynı hash algoritmasını kullanır).
func gravatarHashOrEmpty(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	hash := md5.Sum([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// extractDomain, "user@domain.com" formatındaki bir e-postadan
// "domain.com" kısmını güvenli şekilde ayıklar.
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[1]))
}

// writeJSON, verilen payload'u belirtilen HTTP durum koduyla JSON olarak yazar.
func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError, standart bir hata JSON'ı yazar.
func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Details: details})
}
