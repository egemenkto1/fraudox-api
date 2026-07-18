// Package disposable, bilinen tek kullanımlık (disposable/temporary)
// e-posta sağlayıcılarının alan adı listesini bellekte tutan, thread-safe
// ve periyodik olarak GitHub üzerindeki açık kaynaklı listelerden
// kendini güncelleyen bir arka plan servisi (background worker) sağlar.
package disposable

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"fraud-osint-api/internal/config"
)

// updateInterval, veritabanının ne sıklıkla yenileneceğini belirler.
// Env: DISPOSABLE_UPDATE_INTERVAL_HOURS (bkz. internal/config, default: 24s).
var updateInterval = config.DisposableUpdateInterval

// sourceURLs, bilinen açık kaynaklı disposable e-posta repolarının
// ham (raw) metin listelerinin URL'leridir. Tamamen ücretsiz ve
// herkese açık kaynaklardır; API anahtarı gerektirmezler.
var sourceURLs = []string{
	"https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
	"https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf",
}

// seedDomains, servis ilk açıldığında (henüz internetten liste
// çekilememişken dahi) API'nin sıfır sonuç dönmemesi için kullanılan
// küçük bir başlangıç (fallback) kümesidir.
var seedDomains = []string{
	"mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
	"yopmail.com", "throwawaymail.com", "trashmail.com", "getnada.com",
	"fakeinbox.com", "sharklasers.com",
}

// Store, disposable alan adlarını bellekte tutan thread-safe bir
// veri yapısıdır. Okuma-ağırlıklı bir kullanım deseni için
// sync.RWMutex tercih edilmiştir: eşzamanlı çok sayıda API isteği
// birbirini bloklamadan O(1) hızında arama yapabilir.
type Store struct {
	mu          sync.RWMutex
	domains     map[string]struct{}
	lastUpdated time.Time
	httpClient  *http.Client
}

// NewStore, seed verileriyle önceden doldurulmuş yeni bir Store oluşturur.
func NewStore() *Store {
	s := &Store{
		domains:    make(map[string]struct{}, len(seedDomains)),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	s.mu.Lock()
	for _, d := range seedDomains {
		s.domains[d] = struct{}{}
	}
	s.lastUpdated = time.Now()
	s.mu.Unlock()
	return s
}

// IsDisposable, verilen alan adının bilinen disposable listesinde olup
// olmadığını O(1) karmaşıklıkla kontrol eder. RWMutex sayesinde birden
// fazla goroutine aynı anda güvenle okuma yapabilir.
func (s *Store) IsDisposable(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.domains[domain]
	return exists
}

// Size, veritabanındaki toplam alan adı sayısını döner.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.domains)
}

// LastUpdated, son başarılı güncelleme zamanını döner.
func (s *Store) LastUpdated() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastUpdated
}

// replaceAll, mevcut veri kümesini verilen yeni küme ile tamamen değiştirir.
// Güncelleme sırasında dahi okuyucular tutarlı (eski ya da yeni, hiçbir
// zaman yarı-güncellenmiş) bir görünüm elde eder, çünkü değişim tek bir
// kilit (lock) altında atomik olarak yapılır.
func (s *Store) replaceAll(newDomains map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Seed verilerini her zaman koruyoruz ki bir güncelleme kaynağı
	// başarısız olursa dahi temel koruma devam etsin.
	for _, d := range seedDomains {
		newDomains[d] = struct{}{}
	}
	s.domains = newDomains
	s.lastUpdated = time.Now()
}

// fetchAndParse, verilen URL'den ham metin listesini indirir ve
// satır satır ayrıştırır (yorum satırları "#" ile başlar, boş satırlar
// atlanır).
func (s *Store) fetchAndParse(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("beklenmeyen HTTP durumu: %d", resp.StatusCode)
	}

	var results []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		results = append(results, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// refresh, tüm kaynak URL'lerden eşzamanlı olarak listeleri çeker,
// birleştirir ve Store'u atomik olarak günceller. Herhangi bir kaynak
// başarısız olsa dahi diğer kaynaklardan gelen veriler kullanılır
// (graceful degradation).
func (s *Store) refresh(ctx context.Context) {
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		merged = make(map[string]struct{})
		anyOK  bool
	)

	for _, url := range sourceURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()

			domains, err := s.fetchAndParse(cctx, url)
			if err != nil {
				log.Printf("[disposable] kaynak güncellenemedi (%s): %v", url, err)
				return
			}

			mu.Lock()
			for _, d := range domains {
				merged[d] = struct{}{}
			}
			anyOK = true
			mu.Unlock()
		}(url)
	}

	wg.Wait()

	if anyOK && len(merged) > 0 {
		s.replaceAll(merged)
		log.Printf("[disposable] veritabanı güncellendi: %d alan adı yüklendi", s.Size())
	} else {
		log.Printf("[disposable] hiçbir kaynaktan veri alınamadı, mevcut liste korunuyor (%d alan adı)", s.Size())
	}
}

// StartBackgroundWorker, ilk güncellemeyi hemen (arka planda, bloklamadan)
// başlatır ve ardından her `updateInterval` sürede bir tekrar eden bir
// goroutine döngüsü kurar. Bu fonksiyon çağrıldığı anda hemen döner;
// asıl iş kendi goroutine'i içinde yürütülür. `ctx` iptal edildiğinde
// worker güvenli bir şekilde sonlanır.
func (s *Store) StartBackgroundWorker(ctx context.Context) {
	go func() {
		// İlk yüklemeyi API ayağa kalkar kalkmaz, gecikmeden yap.
		s.refresh(ctx)

		ticker := time.NewTicker(updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[disposable] arka plan servisi durduruldu")
				return
			case <-ticker.C:
				s.refresh(ctx)
			}
		}
	}()
}
