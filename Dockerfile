# syntax=docker/dockerfile:1

# ==============================================================================
# STAGE 1 — Builder
# Go binary'sini statik olarak (CGO_ENABLED=0) derler. Bu, ikinci aşamada
# hiçbir C kütüphanesine (glibc dahil) ihtiyaç duymadan, "distroless"
# gibi son derece minimal bir çalışma zamanı imajında sorunsuz çalışmasını
# sağlar.
# ==============================================================================
FROM golang:1.22-alpine AS builder

# ca-certificates: derleme sırasında `go mod download` gibi HTTPS
# işlemleri ve —daha da önemlisi— bu sertifika paketinin son imaja
# kopyalanacak kopyasını üretmek için gerekli (distroless "static" imajı
# CA sertifikaları içermez; API'nin GitHub/Gravatar gibi HTTPS uçlarına
# istek atabilmesi için bunlar şart).
RUN apk add --no-cache ca-certificates git

WORKDIR /build

# Bağımlılık katmanını ayrı kopyalayarak Docker layer cache'inden
# faydalanıyoruz: go.mod/go.sum değişmediği sürece sonraki build'lerde
# bu katman tekrar indirilmez.
COPY go.mod ./
RUN go mod download 2>/dev/null || true

# Kaynak kodun tamamını kopyala.
COPY . .

# Statik, CGO'suz, küçültülmüş (-s -w ile debug sembolleri atılmış)
# bir binary derle. GOOS/GOARCH sabitlenerek build ortamından bağımsız,
# tekrarlanabilir (reproducible) bir çıktı garanti edilir.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /build/fraudox-api .

# ==============================================================================
# STAGE 2 — Runtime (distroless)
# Google'ın "distroless/static" imajı: içinde shell, paket yöneticisi,
# libc veya herhangi bir Linux dağıtım aracı YOKTUR — yalnızca çalışma
# zamanı için mutlak gereken minimum dosya sistemi bulunur. Bu, saldırı
# yüzeyini (attack surface) ve imaj boyutunu (~2MB taban) drastik şekilde
# azaltır; container içine "girip" (`docker exec sh`) araştırma yapılamaz
# olması dahi ekstra bir güvenlik katmanıdır.
# ==============================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# CA sertifikalarını builder aşamasından kopyala (distroless/static bunu
# içermez; API'nin dış HTTPS servislerine (Gravatar, GitHub) erişebilmesi
# için şart).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Statik binary'yi kopyala.
COPY --from=builder /build/fraudox-api /app/fraudox-api

# distroless:nonroot imajı zaten "nonroot" (UID 65532) kullanıcısıyla
# çalışır; root olarak çalıştırma denemesi bilinçli olarak
# engellenmiştir — bu, container kaçışı (container breakout) senaryolarında
# ek bir savunma katmanıdır.
USER nonroot:nonroot

WORKDIR /app

EXPOSE 8080

# Sağlık kontrolü, container orkestrasyon araçlarının (Docker Swarm,
# Kubernetes readiness/liveness probe'ları vb.) servisin gerçekten
# istek almaya hazır olup olmadığını anlaması için. NOT: distroless
# imajında `curl`/`wget` bulunmadığından, HEALTHCHECK burada bilerek
# tanımlanmamıştır; sağlık kontrolü orkestrasyon katmanında (örn.
# Kubernetes'in kendi HTTP probe mekanizmasıyla, container içinde ayrı
# bir binary'ye ihtiyaç duymadan) /healthz uç noktasına yapılmalıdır.

ENTRYPOINT ["/app/fraudox-api"]
