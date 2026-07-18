// scripts/benchmark.go
//
// Fraudox API için dürüst, şeffaf bir benchmark aracı.
//
// ÖNEMLİ DÜRÜSTLÜK NOTU: API'ye artık IP-bazlı bir rate limiter
// eklendiğinden (dakikada 60 istek/IP), bu aracı TEK bir kaynak IP'den
// (varsayılan davranış) çalıştırırsanız 60. istekten sonra 429'lar
// görürsünüz — bu bir hata değil, rate limiter'ın tam olarak beklendiği
// gibi çalıştığının kanıtıdır. Bu yüzden bu araç iki ayrı, açıkça
// etiketlenmiş modda çalışır:
//
//	-mode=realistic (varsayılan): Tüm istekler tek bir istemci IP'si
//	   gibi davranır (X-Forwarded-For göndermez). Gerçek dünyada tek bir
//	   istemcinin (veya tek bir saldırganın) göreceği deneyimi ölçer.
//	   Rate limiter burada AKTİFTİR ve 429'lar beklenir/raporlanır.
//
//	-mode=raw: Her sanal istemciye farklı bir X-Forwarded-For değeri
//	   atanır, böylece rate limiter'ı atlayarak sunucunun/cache
//	   katmanının HAM işlem kapasitesi (iç kapasite planlaması için)
//	   ölçülür. NOT: Bu, API doğrudan internete açıkken GEÇERLİ bir
//	   güvenlik varsayımı DEĞİLDİR (X-Forwarded-For istemci tarafından
//	   taklit edilebilir); yalnızca güvenilir bir reverse proxy arkasında
//	   X-Forwarded-For'a güvenilebilecek dağıtımlar için ya da saf
//	   kapasite ölçümü amacıyla kullanılmalıdır. Rapor bunu açıkça belirtir.
//
// Her iki modda da iki senaryo test edilir:
//   - cache-miss: her istek benzersiz email+IP kullanır (gerçek DNS +
//     port taraması + Gravatar isteği tetiklenir)
//   - cache-hit:  tek bir sabit email+IP tekrar tekrar kullanılır (ısınmış
//     cache üzerinden yanıtlanır)
//
// Kullanım:
//
//	go run ./scripts -n 2000 -c 50 -mode realistic
//	go run ./scripts -n 20000 -c 200 -mode raw
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// requestFactory, i. isteğin gövdesini ve (varsa) sahte istemci IP'sini üretir.
type requestFactory func(i int) (bodyJSON string, spoofedClientIP string)

// scenarioResult, tek bir senaryonun (cache-hit ya da cache-miss) ölçüm sonucudur.
type scenarioResult struct {
	name          string
	totalRequests int
	successCount  int64 // HTTP 200
	rateLimited   int64 // HTTP 429
	errorCount    int64 // ağ hatası veya beklenmeyen durum kodu
	latencies     []time.Duration
	wallTime      time.Duration
}

func main() {
	var (
		baseURL     = flag.String("url", "http://localhost:8080", "API taban URL'si")
		n           = flag.Int("n", 2000, "senaryo başına toplam istek sayısı")
		concurrency = flag.Int("c", 50, "eşzamanlı worker (goroutine) sayısı")
		mode        = flag.String("mode", "realistic", "'realistic' (tek IP, rate-limit aktif) veya 'raw' (IP-spoofed, rate-limit bypass, ham kapasite)")
	)
	flag.Parse()

	if *mode != "realistic" && *mode != "raw" {
		fmt.Fprintln(os.Stderr, "hata: -mode 'realistic' veya 'raw' olmalı")
		os.Exit(1)
	}

	fmt.Println(strings.Repeat("=", 78))
	fmt.Println("FRAUDOX API — DÜRÜST BENCHMARK RAPORU")
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("Hedef:        %s\n", *baseURL)
	fmt.Printf("İstek/senaryo: %d   Eşzamanlılık: %d   Mod: %s\n", *n, *concurrency, *mode)
	if *mode == "realistic" {
		fmt.Println("\n[NOT] 'realistic' modda TEK bir istemci IP'si simüle edilir.")
		fmt.Println("      Rate limiter (60 istek/dk/IP) AKTİFTİR; 60. istekten sonra")
		fmt.Println("      429 yanıtları görmeniz BEKLENEN ve DOĞRU bir davranıştır.")
	} else {
		fmt.Println("\n[UYARI] 'raw' modda her istek farklı bir X-Forwarded-For ile")
		fmt.Println("        gönderilir; bu rate limiter'ı KASITLI olarak by-pass eder.")
		fmt.Println("        Bu sayılar GERÇEK DÜNYA kapasitesini DEĞİL, sunucunun/cache")
		fmt.Println("        katmanının teorik tavanını gösterir. Üretim SLA'sı olarak")
		fmt.Println("        KULLANILMAMALIDIR.")
	}
	fmt.Println(strings.Repeat("=", 78))

	client := &http.Client{Timeout: 10 * time.Second}

	// --- Senaryo 1: cache-miss ---
	// Her istek benzersiz bir email ve TEST-NET-1 (RFC 5737, 192.0.2.0/24)
	// aralığından benzersiz bir IP kullanır; bu aralık belgeleme/test
	// amaçlıdır, gerçek hiçbir hosta ait değildir, bu yüzden port
	// taraması güvenle "kapalı" sonucu dönerken gerçek bir ağ maliyeti
	// (500ms timeout) üretir — tam olarak istenen "cache-miss" senaryosu.
	missFactory := func(i int) (string, string) {
		email := fmt.Sprintf("bench-miss-%d-%d@example-%d.com", time.Now().UnixNano(), i, i%5000)
		ip := fmt.Sprintf("192.0.2.%d", (i%254)+1)
		spoofIP := ""
		if *mode == "raw" {
			spoofIP = fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
		}
		return fmt.Sprintf(`{"email":%q,"ip":%q}`, email, ip), spoofIP
	}
	missResult := runScenario(client, *baseURL, "cache-miss", *n, *concurrency, *mode, missFactory)

	// --- Isınma (warm-up): cache-hit senaryosu için sabit email/IP'yi önceden çağır ---
	warmUpBody := `{"email":"bench-hit-fixed@gmail.com","ip":"198.51.100.7"}`
	_, _ = client.Post(*baseURL+"/api/v1/analyze", "application/json", bytes.NewBufferString(warmUpBody))
	time.Sleep(200 * time.Millisecond) // cache yazımının kesinleşmesi için kısa bekleme

	// --- Senaryo 2: cache-hit ---
	// Tüm istekler AYNI email+IP'yi kullanır; DNS/port/Gravatar cache'i
	// zaten ısındığı için gerçek I/O yerine sadece bellek erişimi yapılır.
	hitFactory := func(i int) (string, string) {
		spoofIP := ""
		if *mode == "raw" {
			spoofIP = fmt.Sprintf("172.16.%d.%d", (i/256)%256, i%256)
		}
		return warmUpBody, spoofIP
	}
	hitResult := runScenario(client, *baseURL, "cache-hit", *n, *concurrency, *mode, hitFactory)

	printReport(missResult, hitResult)
}

// runScenario, verilen requestFactory ile n istekten oluşan bir yükü
// concurrency kadar goroutine üzerinden eşzamanlı gönderir, her isteğin
// gecikmesini ve durumunu kaydeder.
func runScenario(client *http.Client, baseURL, name string, n, concurrency int, mode string, factory requestFactory) *scenarioResult {
	result := &scenarioResult{name: name, totalRequests: n}

	var (
		latMu     sync.Mutex
		wg        sync.WaitGroup
		jobs      = make(chan int, n)
		successes int64
		limited   int64
		errs      int64
	)

	latencies := make([]time.Duration, 0, n)

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			body, spoofIP := factory(i)

			req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/analyze", bytes.NewBufferString(body))
			if err != nil {
				atomic.AddInt64(&errs, 1)
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			if mode == "raw" && spoofIP != "" {
				req.Header.Set("X-Forwarded-For", spoofIP)
			}

			start := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(start)

			if err != nil {
				atomic.AddInt64(&errs, 1)
				continue
			}
			_ = resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				atomic.AddInt64(&successes, 1)
				latMu.Lock()
				latencies = append(latencies, elapsed)
				latMu.Unlock()
			case http.StatusTooManyRequests:
				atomic.AddInt64(&limited, 1)
			default:
				atomic.AddInt64(&errs, 1)
			}
		}
	}

	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Add(concurrency)
	start := time.Now()
	for i := 0; i < concurrency; i++ {
		go worker()
	}
	wg.Wait()
	result.wallTime = time.Since(start)

	result.successCount = successes
	result.rateLimited = limited
	result.errorCount = errs
	result.latencies = latencies

	return result
}

// percentile, sıralanmış bir gecikme dilimi üzerinden verilen yüzdelik
// dilimi (0-100) hesaplar (en yakın indekse yuvarlayarak; harici
// istatistik kütüphanesi kullanmadan basit ve yeterince doğru bir yöntem).
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int((p / 100.0) * float64(len(sorted)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func printReport(scenarios ...*scenarioResult) {
	fmt.Println()
	fmt.Println(strings.Repeat("-", 78))
	fmt.Printf("%-14s %10s %10s %10s %12s %10s %10s\n",
		"Senaryo", "Başarılı", "429", "Hata", "RPS", "p50", "p99")
	fmt.Println(strings.Repeat("-", 78))

	for _, r := range scenarios {
		sort.Slice(r.latencies, func(i, j int) bool { return r.latencies[i] < r.latencies[j] })

		rps := 0.0
		if r.wallTime.Seconds() > 0 {
			rps = float64(r.successCount) / r.wallTime.Seconds()
		}

		p50 := percentile(r.latencies, 50)
		p99 := percentile(r.latencies, 99)

		fmt.Printf("%-14s %10d %10d %10d %12.1f %10s %10s\n",
			r.name, r.successCount, r.rateLimited, r.errorCount, rps,
			formatDuration(p50), formatDuration(p99))
	}
	fmt.Println(strings.Repeat("-", 78))

	fmt.Println()
	fmt.Println("YORUMLAMA REHBERİ:")
	fmt.Println("  - 'cache-miss' satırı, sisteme hiç görmediği email/IP kombinasyonları")
	fmt.Println("    gönderildiğinde gerçek DNS + port taraması + Gravatar maliyetini yansıtır.")
	fmt.Println("    Bu, üretimdeki 'ilk kez görülen istek' maliyetinin gerçekçi tahminidir.")
	fmt.Println("  - 'cache-hit' satırı, TTL cache'in en iyi senaryodaki (ısınmış) tavanını")
	fmt.Println("    gösterir; gerçek trafik deseninize bağlı olarak asıl ortalama")
	fmt.Println("    performansınız bu iki değer arasında bir yerde olacaktır.")
	fmt.Println("  - '429' sütunundaki değerler, rate limiter'ın çalıştığının kanıtıdır;")
	fmt.Println("    'realistic' modda cache-miss/cache-hit fark etmeksizin 60'tan sonraki")
	fmt.Println("    her istek 429 alır çünkü sınırlama IP bazlıdır, cache durumundan bağımsızdır.")
	fmt.Println()
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0)
}

// randSeed, farklı çalıştırmalar arasında email varyasyonunu artırmak
// için kullanılabilir (şu an deterministik i-bazlı üretim yeterli olduğu
// için doğrudan kullanılmıyor, ama gelecekte -seed flag'i eklenmek
// istenirse hazır bir temel oluşturur).
var _ = rand.Int
