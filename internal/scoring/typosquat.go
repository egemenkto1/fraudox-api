// Package scoring, risk puanlama motorunun tüm alt modüllerini
// (typo-squat, DNS, sosyal ayak izi, port tarama) içerir.
package scoring

import (
	"strings"

	"fraud-osint-api/internal/models"
)

// KnownEmailProviders, dünyanın en popüler ~50 e-posta sağlayıcısının
// alan adı listesidir. Bu liste, typo-squatting tespiti için referans
// (ground-truth) kümesi olarak kullanılır.
var KnownEmailProviders = []string{
	"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
	"aol.com", "protonmail.com", "zoho.com", "mail.com", "gmx.com",
	"yandex.com", "live.com", "msn.com", "me.com", "mac.com",
	"fastmail.com", "hushmail.com", "tutanota.com", "rocketmail.com", "ymail.com",
	"comcast.net", "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
	"cox.net", "charter.net", "earthlink.net", "juno.com", "netzero.net",
	"qq.com", "163.com", "126.com", "sina.com", "naver.com",
	"daum.net", "rediffmail.com", "inbox.com", "lycos.com", "excite.com",
	"web.de", "gmx.de", "t-online.de", "orange.fr", "laposte.net",
	"libero.it", "virgilio.it", "seznam.cz", "walla.com", "mail.ru",
	"outlook.com.tr", "hotmail.com.tr", "yahoo.com.tr", "superonline.com", "ttmail.com",
}

// levenshteinDistance, iki string arasındaki minimum düzenleme
// mesafesini (ekleme, silme, değiştirme) klasik dinamik programlama
// yaklaşımıyla hesaplar. O(n*m) zaman ve alan karmaşıklığına sahiptir.
func levenshteinDistance(a, b string) int {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// 2 satırlık rolling matrix kullanarak bellek kullanımını optimize ediyoruz.
	prevRow := make([]int, lb+1)
	currRow := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prevRow[j] = j
	}

	for i := 1; i <= la; i++ {
		currRow[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			deletion := prevRow[j] + 1
			insertion := currRow[j-1] + 1
			substitution := prevRow[j-1] + cost
			currRow[j] = min3(deletion, insertion, substitution)
		}
		prevRow, currRow = currRow, prevRow
	}

	return prevRow[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// similarityPercent, Levenshtein mesafesini iki string'in maksimum
// uzunluğuna göre normalize ederek 0-100 arası bir benzerlik yüzdesi üretir.
func similarityPercent(distance, maxLen int) float64 {
	if maxLen == 0 {
		return 100.0
	}
	return (1.0 - float64(distance)/float64(maxLen)) * 100.0
}

// AnalyzeTyposquat, verilen e-posta alan adını bilinen sağlayıcı listesiyle
// karşılaştırır. Alan adı bilinen bir sağlayıcıyla birebir eşleşmiyorsa
// ancak %90'ın üzerinde benzerlik gösteriyorsa, phishing/typo-squatting
// şüphesi olarak işaretlenir (örn: "gmial.com" -> "gmail.com").
func AnalyzeTyposquat(domain string) models.TypoSquatResult {
	domain = strings.ToLower(strings.TrimSpace(domain))

	result := models.TypoSquatResult{
		Domain: domain,
	}

	// Önce birebir (exact match) kontrolü yapılır. Bilinen bir sağlayıcıysa
	// zaten güvenlidir, karşılaştırma yapmaya gerek yoktur.
	for _, provider := range KnownEmailProviders {
		if domain == provider {
			result.IsKnownProvider = true
			return result
		}
	}

	// Bilinen sağlayıcı değilse, listedeki her bir alan adına olan
	// Levenshtein mesafesini hesaplayıp en yakın eşleşmeyi buluruz.
	bestMatch := ""
	bestDistance := 1 << 30
	bestSimilarity := 0.0

	for _, provider := range KnownEmailProviders {
		dist := levenshteinDistance(domain, provider)
		maxLen := len(domain)
		if len(provider) > maxLen {
			maxLen = len(provider)
		}
		sim := similarityPercent(dist, maxLen)

		if dist < bestDistance {
			bestDistance = dist
			bestMatch = provider
			bestSimilarity = sim
		}
	}

	result.ClosestMatch = bestMatch
	result.LevenshteinDistance = bestDistance
	result.SimilarityPercent = roundTo2(bestSimilarity)

	// Benzerlik >= %90 ise ve birebir eşleşme değilse -> şüpheli typo-squat.
	// (örn: "gmaill.com" -> "gmail.com", mesafe=1, benzerlik=%90)
	if bestSimilarity >= 90.0 {
		result.IsSuspiciousTyposquat = true
		result.RiskContribution = 45 // Yüksek risk: aktif phishing girişimi olabilir.
	}

	return result
}

func roundTo2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
