package handler

import (
	"net/http"
	"os"
)

// GatewayAuthMiddleware validates requests from authorized API gateways (RapidAPI and Zyla API Hub).
func GatewayAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rapidAPISecret := os.Getenv("RAPIDAPI_PROXY_SECRET")
		zylaSecret := os.Getenv("ZYLA_PROXY_SECRET")
		
		// Bypass validation for local development environments when no secrets are provided
		if rapidAPISecret == "" && zylaSecret == "" {
			next.ServeHTTP(w, r)
			return
		}

		clientRapidSecret := r.Header.Get("X-RapidAPI-Proxy-Secret")
		clientZylaSecret := r.Header.Get("X-Zyla-Proxy-Secret")

		// Validate incoming headers against environment variables
		validRapid := rapidAPISecret != "" && clientRapidSecret == rapidAPISecret
		validZyla := zylaSecret != "" && clientZylaSecret == zylaSecret

		// Deny access if neither gateway provides a valid proxy secret
		if !validRapid && !validZyla {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Forbidden: Unauthorized gateway access detected."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
