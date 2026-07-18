// Fraud Detection & OSINT Scoring API
//
// Bu servis, verilen bir e-posta adresi ve IP adresi için 5 bağımsız
// OSINT modülünü (typo-squat tespiti, DNS güvenliği, sosyal ayak izi,
// proxy/VPN port taraması ve disposable e-posta veritabanı) çalıştırarak
// 0-100 arasında bir risk skoru ve nihai bir karar (ALLOW/REVIEW/BLOCK)
// üretir. Tamamen Go standart kütüphanesi ve ücretsiz açık kaynaklara
// dayanır; hiçbir ücretli üçüncü parti API kullanılmaz.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fraud-osint-api/internal/config"
	"fraud-osint-api/internal/disposable"
	"fraud-osint-api/internal/handler"
)

const (
	readHeaderTimeout   = 5 * time.Second
	serverReadTimeout   = 10 * time.Second
	serverWriteTimeout  = 15 * time.Second
	serverIdleTimeout   = 60 * time.Second
	shutdownGracePeriod = 10 * time.Second
)

func main() {
	log.Println("[main] Fraud Detection & OSINT Scoring API başlatılıyor...")

	// Uygulama genelinde kullanılacak, arka plan worker'ının ve tüm
	// isteklerin iptal sinyali için ortak bir kök context oluşturuyoruz.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Modül 5: Disposable e-posta veritabanı, seed veriyle hemen hazır
	// hale gelir; arka plan worker'ı ilk tam güncellemeyi (GitHub'dan)
	// asenkron olarak indirir ve her 24 saatte bir tekrarlar.
	disposableStore := disposable.NewStore()
	disposableStore.StartBackgroundWorker(appCtx)

	analyzeHandler := handler.NewAnalyzeHandler(disposableStore)

	// Rate limiter: IP başına dakikada 60 istekle sınırlar. Yalnızca
	// /api/v1/analyze uç noktasına uygulanır; /healthz sağlık kontrolü
	// (load balancer/orkestrasyon araçları tarafından sık çağrılır)
	// bilerek sınırlamanın dışında tutulur.
	rateLimiter := handler.NewRateLimiter()

	mux := http.NewServeMux()
	mux.Handle("/api/v1/analyze", rateLimiter.Middleware(analyzeHandler))
	mux.HandleFunc("/healthz", healthCheckHandler)

	port := config.Port

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	// Sunucuyu ayrı bir goroutine'de başlatıyoruz ki ana goroutine
	// OS sinyallerini dinleyip graceful shutdown yapabilsin.
	go func() {
		log.Printf("[main] HTTP sunucusu :%s portunda dinliyor", port)
		log.Printf("[main] Uç nokta: POST http://localhost:%s/api/v1/analyze", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[main] sunucu başlatılamadı: %v", err)
		}
	}()

	// SIGINT / SIGTERM sinyallerini bekleyip düzgün (graceful) kapanış yapıyoruz.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[main] kapatma sinyali alındı, sunucu düzgün şekilde kapatılıyor...")
	appCancel() // Arka plan worker'ını durdur.

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("[main] sunucu düzgün kapatılamadı: %v", err)
	}

	log.Println("[main] sunucu başarıyla kapatıldı")
}

// healthCheckHandler, sağlık kontrolü (health check) uç noktasıdır;
// yük dengeleyiciler ve orkestrasyon araçları (Kubernetes vb.) için kullanılır.
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
