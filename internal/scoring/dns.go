package scoring

import (
	"context"
	"strings"

	"fraud-osint-api/internal/cache"
	"fraud-osint-api/internal/config"
	"fraud-osint-api/internal/models"
)

// dnsTimeout, her bir DNS sorgusu için maksimum bekleme süresidir.
// Yavaş/yanıt vermeyen DNS sunucularının API'yi bloklamasını önler.
// NOT: AnalyzeHandler'daki config.GlobalRequestTimeout (varsayılan
// 800ms) bu değerden daha kısıtlayıcı olduğu için pratikte çağrı ctx
// iptaliyle daha erken sonlanır; bu değer yine de goroutine'in kendi
// başına sonsuza dek bloklamamasını garanti eden bir güvenlik ağıdır.
var dnsTimeout = config.DNSTimeout

// dnsCacheTTL, bir alan adı için DNS sonuçlarının ne kadar süre
// önbellekte tutulacağını belirler. MX/SPF/DMARC kayıtları saatler/günler
// mertebesinde değişir; bu nedenle kısa vadeli tekrarlanan istekler
// (örn. yük testi, aynı domain'den çok sayıda kayıt) gerçek bir DNS
// sorgusu yapmadan önbellekten yanıtlanabilir.
var dnsCacheTTL = config.DNSCacheTTL

// dnsResultCache, domain -> models.DNSResult eşlemesini tutan paket
// seviyesinde paylaşılan bir cache'tir. Thread-safe olduğu için tüm
// eşzamanlı istekler güvenle kullanabilir.
var dnsResultCache = cache.New(dnsCacheTTL)

// AnalyzeDNS, verilen alan adı için genel çözümlenebilirlik (A/AAAA),
// MX, SPF ve DMARC kayıtlarını eşzamanlı (concurrent) olarak sorgular.
// Sonuçlar dnsCacheTTL süresince önbelleğe alınır. Go'nun net paketi ve
// context tabanlı zaman aşımı mekanizması kullanılır; harici hiçbir
// servise bağımlılık yoktur.
func AnalyzeDNS(ctx context.Context, domain string) models.DNSResult {
	// --- Önbellek kontrolü ---
	if cached, ok := dnsResultCache.Get(domain); ok {
		if result, ok := cached.(models.DNSResult); ok {
			result.FromCache = true
			return result
		}
	}

	result := models.DNSResult{Domain: domain}

	var resolver netResolverImpl

	// dört bağımsız sorgu paralel goroutine'lerde çalışır; sonuçlar
	// kanallar üzerinden toplanır.
	type outcome struct {
		records []string
		err     error
	}

	hostCh := make(chan outcome, 1)
	mxCh := make(chan outcome, 1)
	rootTxtCh := make(chan outcome, 1)
	dmarcTxtCh := make(chan outcome, 1)

	go func() {
		cctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		recs, err := resolver.lookupHost(cctx, domain)
		hostCh <- outcome{records: recs, err: err}
	}()

	go func() {
		cctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		recs, err := resolver.lookupMX(cctx, domain)
		mxCh <- outcome{records: recs, err: err}
	}()

	go func() {
		cctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		recs, err := resolver.lookupTXT(cctx, domain)
		rootTxtCh <- outcome{records: recs, err: err}
	}()

	go func() {
		cctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		recs, err := resolver.lookupTXT(cctx, "_dmarc."+domain)
		dmarcTxtCh <- outcome{records: recs, err: err}
	}()

	hostRes := <-hostCh
	mxRes := <-mxCh
	rootTxtRes := <-rootTxtCh
	dmarcRes := <-dmarcTxtCh

	// --- Genel çözümlenebilirlik (A/AAAA) — MX/TXT'ten TAMAMEN bağımsız ---
	// Bu, "alan adı hiç yok" durumunun tek doğru kaynağıdır. SPF/DMARC
	// sorgularının başarılı olması da domain'in var olduğunu gösterebilir
	// (bazı DNS sunucuları A kaydı olmayan ama TXT kaydı olan domainler
	// için farklı davranabilir), bu yüzden ikisinden biri başarılıysa
	// domain resolvable kabul edilir.
	if hostRes.err == nil && len(hostRes.records) > 0 {
		result.DomainResolvable = true
	} else if rootTxtRes.err == nil {
		result.DomainResolvable = true
	} else {
		result.DomainResolvable = false
		if hostRes.err != nil {
			result.ResolveError = hostRes.err.Error()
		}
	}

	// --- MX değerlendirmesi (kendi hatası ayrı alanda tutulur) ---
	if mxRes.err == nil && len(mxRes.records) > 0 {
		result.HasMXRecord = true
		result.MXRecords = mxRes.records
	} else if mxRes.err != nil {
		result.MXLookupError = mxRes.err.Error()
	}

	// --- SPF değerlendirmesi (kök alan adının TXT kayıtları içinde "v=spf1" aranır) ---
	if rootTxtRes.err == nil {
		for _, txt := range rootTxtRes.records {
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				result.HasSPFRecord = true
				result.SPFRecord = txt
				break
			}
		}
	}

	// --- DMARC değerlendirmesi (_dmarc alt alan adının TXT kaydı içinde "v=DMARC1" aranır) ---
	if dmarcRes.err == nil {
		for _, txt := range dmarcRes.records {
			if strings.HasPrefix(strings.ToUpper(txt), "V=DMARC1") {
				result.HasDMARCRecord = true
				result.DMARCRecord = txt
				break
			}
		}
	}

	// --- Risk puanlaması ---
	if !result.DomainResolvable {
		// Alan adı DNS'te hiç yoksa (NXDOMAIN), bu tek başına ciddi bir
		// uyarı işaretidir; diğer tüm alt puanların yerine sabit bir
		// maksimum ceza uygulanır.
		result.RiskContribution = 50
	} else {
		risk := 0
		if !result.HasMXRecord {
			// Domain var ama e-posta alamıyor; typosquat/parked domain olabilir.
			risk += 30
		}
		if !result.HasSPFRecord {
			risk += 10
		}
		if !result.HasDMARCRecord {
			risk += 10
		}
		result.RiskContribution = risk
	}

	// Sonucu önbelleğe yaz (5 dakika geçerli). FromCache=false olarak
	// saklanır; cache'ten okunduğunda Get sonrası true'ya çevrilir.
	dnsResultCache.Set(domain, result)

	return result
}
