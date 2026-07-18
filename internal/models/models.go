// Package models, API genelinde kullanılan istek/yanıt ve iç veri
// yapılarını (struct) tanımlar. Tüm modüller bu paketi referans alarak
// tutarlı bir veri sözleşmesi (contract) üzerinde çalışır.
package models

import "time"

// AnalyzeRequest, POST /api/v1/analyze uç noktasına gönderilen istek gövdesidir.
type AnalyzeRequest struct {
	Email string `json:"email"`
	IP    string `json:"ip"`
}

// Verdict, nihai risk kararını temsil eden string tip.
type Verdict string

const (
	VerdictAllow  Verdict = "ALLOW"
	VerdictReview Verdict = "REVIEW"
	VerdictBlock  Verdict = "BLOCK"
)

// TypoSquatResult, Modül 1 - Typo-Squatting/Phishing tespit sonucudur.
type TypoSquatResult struct {
	Domain                string  `json:"domain"`
	IsKnownProvider       bool    `json:"is_known_provider"`
	ClosestMatch          string  `json:"closest_match,omitempty"`
	SimilarityPercent     float64 `json:"similarity_percent,omitempty"`
	LevenshteinDistance   int     `json:"levenshtein_distance,omitempty"`
	IsSuspiciousTyposquat bool    `json:"is_suspicious_typosquat"`
	RiskContribution      int     `json:"risk_contribution"`
}

// DNSResult, Modül 2 - DNS güvenliği ve doğrulama sonucudur.
// DomainResolvable, alan adının DNS'te genel olarak var olup olmadığını
// (bağımsız bir A/AAAA sorgusuyla) gösterir. Bu bilerek MX/SPF/DMARC'tan
// AYRI tutulur: bir alan adının A kaydı olup MX kaydı olmaması (örn.
// sadece web sitesi olan, e-posta almayan bir domain) tamamen normaldir
// ve "alan adı yok/çözümlenemiyor" anlamına gelmemelidir. Her kayıt
// tipinin kendi hatası kendi alanında tutulur ki "domain hiç yok" ile
// "sadece MX kaydı yok" durumları JSON çıktısında karışmasın.
type DNSResult struct {
	Domain           string   `json:"domain"`
	DomainResolvable bool     `json:"domain_resolvable"`
	ResolveError     string   `json:"resolve_error,omitempty"`
	HasMXRecord      bool     `json:"has_mx_record"`
	MXRecords        []string `json:"mx_records,omitempty"`
	MXLookupError    string   `json:"mx_lookup_error,omitempty"`
	HasSPFRecord     bool     `json:"has_spf_record"`
	SPFRecord        string   `json:"spf_record,omitempty"`
	HasDMARCRecord   bool     `json:"has_dmarc_record"`
	DMARCRecord      string   `json:"dmarc_record,omitempty"`
	FromCache        bool     `json:"from_cache"`
	TimedOut         bool     `json:"timed_out,omitempty"`
	RiskContribution int      `json:"risk_contribution"`
}

// SocialFootprintResult, Modül 3 - Gravatar tabanlı sosyal ayak izi sonucudur.
type SocialFootprintResult struct {
	EmailMD5         string `json:"email_md5"`
	GravatarExists   bool   `json:"gravatar_exists"`
	GravatarURL      string `json:"gravatar_url,omitempty"`
	HTTPStatusCode   int    `json:"http_status_code,omitempty"`
	CheckError       string `json:"check_error,omitempty"`
	FromCache        bool   `json:"from_cache"`
	TimedOut         bool   `json:"timed_out,omitempty"`
	RiskContribution int    `json:"risk_contribution"` // negatif değer risk azaltır
}

// OpenPort, taranan bir portun sonucunu temsil eder.
type OpenPort struct {
	Port        int    `json:"port"`
	IsOpen      bool   `json:"is_open"`
	ServiceHint string `json:"service_hint"`
}

// PortScanResult, Modül 4 - Proxy/VPN port tarama sonucudur.
type PortScanResult struct {
	IP               string     `json:"ip"`
	ValidIP          bool       `json:"valid_ip"`
	ScannedPorts     []OpenPort `json:"scanned_ports"`
	AnyProxyPortOpen bool       `json:"any_proxy_port_open"`
	ScanDurationMs   int64      `json:"scan_duration_ms"`
	FromCache        bool       `json:"from_cache"`
	TimedOut         bool       `json:"timed_out,omitempty"`
	RiskContribution int        `json:"risk_contribution"`
}

// DisposableResult, Modül 5 - Tek kullanımlık e-posta kontrolü sonucudur.
type DisposableResult struct {
	Domain             string    `json:"domain"`
	IsDisposable       bool      `json:"is_disposable"`
	DatabaseSize       int       `json:"database_size"`
	DatabaseLastUpdate time.Time `json:"database_last_updated"`
	RiskContribution   int       `json:"risk_contribution"`
}

// AnalyzeResponse, API'nin döndürdüğü nihai, yapılandırılmış kurumsal yanıttır.
type AnalyzeResponse struct {
	Email           string                `json:"email"`
	IP              string                `json:"ip"`
	RiskScore       int                   `json:"risk_score"` // 0-100
	Verdict         Verdict               `json:"verdict"`
	TypoSquat       TypoSquatResult       `json:"typo_squat_analysis"`
	DNS             DNSResult             `json:"dns_analysis"`
	SocialFootprint SocialFootprintResult `json:"social_footprint_analysis"`
	PortScan        PortScanResult        `json:"port_scan_analysis"`
	Disposable      DisposableResult      `json:"disposable_email_analysis"`
	// PartialResult, GlobalRequestTimeout süresi dolduğunda ve bir veya
	// daha fazla modül (DNS/Gravatar/Port taraması) yetişemediğinde true
	// olur. Bu durumda RiskScore, yalnızca zamanında tamamlanan
	// modüllerin sinyalleriyle hesaplanmış bir "Kısmi Puan"dır.
	PartialResult    bool      `json:"partial_result"`
	SkippedModules   []string  `json:"skipped_modules,omitempty"`
	ProcessingTimeMs int64     `json:"processing_time_ms"`
	Timestamp        time.Time `json:"timestamp"`
}

// ErrorResponse, hatalı isteklerde döndürülen standart hata yanıtıdır.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
