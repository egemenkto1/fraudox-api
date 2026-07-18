package handler

import (
	"net/http"
	"os"
)

// RapidAPIAuthMiddleware, gelen isteklerin sadece RapidAPI üzerinden gelmesini zorunlu kılar.
func RapidAPIAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedSecret := os.Getenv("RAPIDAPI_PROXY_SECRET")
		
		// Eğer ortamda şifre yoksa (lokal test ortamı), direkt içeri al.
		if expectedSecret == "" {
			next.ServeHTTP(w, r)
			return
		}

		// İstekteki şifre ile ortamdaki şifre eşleşmiyorsa 403 yapıştır.
		clientSecret := r.Header.Get("X-RapidAPI-Proxy-Secret")
		if clientSecret != expectedSecret {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Forbidden: Sadece yetkili RapidAPI proxy'si erisebilir."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
