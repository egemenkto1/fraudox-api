# Fraudox API — Fraud Detection & OSINT Scoring

Go standart kütüphanesi ve ücretsiz/açık kaynak yöntemlerle geliştirilmiş,
yüksek performanslı, asenkron bir dolandırıcılık/OSINT risk puanlama API'si.
Hiçbir ücretli üçüncü parti servise veya API anahtarına bağımlılık yoktur.

**Durum:** Production-Ready — thread-safe TTL cache, IP bazlı rate limiting,
dürüst/şeffaf benchmark raporlaması ve distroless Docker paketlemesi ile
tamamlanmıştır.

---

## İçindekiler

- [Hızlı Başlangıç](#hızlı-başlangıç)
- [API Kullanımı](#api-kullanımı)
- [Mimari](#mimari)
- [Mühendislik Yaklaşımımız](#mühendislik-yaklaşımımız)
  - [TTL Cache Mimarisi](#1-ttl-cache-mimarisi)
  - [Concurrency (Goroutine) Tasarımı](#2-concurrency-goroutine-tasarımı)
  - [IP Validation ve Girdi Doğrulama](#3-ip-validation-ve-girdi-doğrulama)
  - [Rate Limiting](#4-rate-limiting)
- [Performans: v1 → v2 → v3 Karşılaştırması](#performans-v1--v2--v3-karşılaştırması)
- [Benchmark Aracı](#benchmark-aracı)
- [Risk Skorlama Ağırlıkları](#risk-skorlama-ağırlıkları)
- [Docker ile Çalıştırma](#docker-ile-çalıştırma)
- [Değişiklik Geçmişi](#değişiklik-geçmişi)

---

## Hızlı Başlangıç

```bash
go mod tidy   # harici bağımlılık yoktur, yalnızca stdlib
go run .
```

Sunucu varsayılan olarak `:8080` portunda ayağa kalkar (`PORT` env değişkeni ile değiştirilebilir).

## API Kullanımı

```bash
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"email":"test@gmaill.com","ip":"8.8.8.8"}'
```

Sağlık kontrolü: `GET /healthz` (rate limiter'ın dışında tutulur, orkestrasyon
araçlarının serbestçe kullanabilmesi için).

## Mimari

```
main.go                              HTTP sunucu, graceful shutdown, worker/middleware wiring
internal/models/                     Tüm istek/yanıt struct'ları (JSON sözleşmesi)
internal/cache/                      Genel amaçlı, thread-safe TTL cache (DNS/port/Gravatar ortak altyapısı)
internal/scoring/typosquat.go        Modül 1: Levenshtein tabanlı typo-squat tespiti
internal/scoring/dns.go, resolver_impl.go   Modül 2: MX/SPF/DMARC doğrulama + DNS cache
internal/scoring/social.go           Modül 3: Gravatar tabanlı sosyal ayak izi + Gravatar cache
internal/scoring/portscan.go         Modül 4: Proxy/VPN port taraması + port cache
internal/disposable/                 Modül 5: Arka plan worker + thread-safe in-memory store
internal/handler/analyze.go          HTTP handler, orkestrasyon, risk skorlama motoru
internal/handler/ratelimit.go        IP bazlı token-bucket rate limiter middleware
scripts/benchmark.go                 Dürüst, iki-modlu (realistic/raw) benchmark aracı
Dockerfile                           Multi-stage, distroless production imajı
```

---

## Mühendislik Yaklaşımımız

Bu bölüm, projenin "çalışıyor" seviyesinden "production-ready" seviyeye
taşınmasında alınan mimari kararları ve bunların gerekçelerini belgeler.

### 1. TTL Cache Mimarisi

`internal/cache/ttlcache.go`, tüm I/O-ağırlıklı modüllerin (DNS, port
tarama, Gravatar) ortak olarak kullandığı, bağımsız, jenerik bir
`sync.RWMutex` tabanlı TTL cache'tir. Tasarım ilkeleri:

- **Okuma-ağırlıklı optimize edilmiş:** `RWMutex` sayesinde çok sayıda
  eşzamanlı istek, birbirini bloklamadan aynı anda okuma yapabilir; yazma
  yalnızca yeni/süresi dolmuş bir anahtar güncellenirken kilitlenir.
- **Modüle özel TTL:** DNS ve port tarama sonuçları 5 dakika, Gravatar
  sonuçları 1 saat önbellekte tutulur — her modülün "gerçekte ne sıklıkla
  değiştiği" ayrı ayrı değerlendirilerek belirlenmiştir (bir MX kaydı
  saatler içinde değişebilirken bir kişinin Gravatar'ı olması/olmaması
  çok daha durağandır).
- **Sadece kesin sonuçlar cache'lenir:** Ağ hataları veya belirsiz durum
  kodları (örn. Gravatar'dan gelen 403) bilinçli olarak önbelleğe
  YAZILMAZ; aksi halde geçici bir kesinti, TTL süresi boyunca yanlış
  sonucun tekrar tekrar dönmesine sebep olurdu.
- **Şeffaflık:** Her yanıtta `from_cache: true/false` alanı bulunur;
  istemci bir sonucun taze mi yoksa önbellekten mi geldiğini her zaman
  bilir — "gizli" bir davranış yoktur.
- **Bellek sınırlaması:** Arka planda çalışan bir `janitor` goroutine'i,
  süresi dolmuş kayıtları periyodik olarak temizler; aksi halde her
  farklı domain/IP/email için map sonsuza dek büyürdü.

### 2. Concurrency (Goroutine) Tasarımı

- DNS sorguları (A/AAAA, MX, kök TXT, `_dmarc` TXT) **4 bağımsız
  goroutine'de** paralel çalışır; her biri kendi `context.WithTimeout`'una
  sahiptir, böylece yavaş bir DNS sunucusu diğer sorguları bloklamaz.
- Port tarama, 4 hedef portu (1080/3128/8080/1194) **4 ayrı goroutine'de**
  `sync.WaitGroup` ile paralel dener (her biri 500ms `DialTimeout`);
  sıralı taramaya göre ~4x daha hızlıdır.
- `/analyze` handler'ı seviyesinde: DNS, Gravatar ve port tarama modülleri
  birbirinden bağımsız **3 goroutine'de eşzamanlı** çalışırken, hızlı/
  CPU-bound olan typo-squat ve disposable kontrolleri ana goroutine'de
  senkron yürütülür; tüm sonuçlar `sync.WaitGroup` ile birleştirilir.
- Disposable e-posta veritabanı `sync.RWMutex` ile korunur; arka plan
  worker'ı bağımsız bir goroutine + `time.Ticker` ile her 24 saatte bir
  GitHub'daki açık kaynak listelerini paralel indirip birleştirir
  (graceful degradation: bir kaynak başarısız olsa dahi diğerinden gelen
  veri kullanılır, güncelleme atomik bir `replaceAll` ile yapılır ki
  okuyucular yarı-güncellenmiş veri görmesin).
- Rate limiter'daki her IP'nin kendi `visitor` kilidine sahip olması
  (global tek bir kilit yerine), farklı IP'lerden gelen isteklerin
  birbirini beklemeden eşzamanlı işlenmesini sağlar.

**Kanıt:** DNS + port tarama + Gravatar sorgularının gerçekten paralel
çalıştığı, cache devreye girmeden önceki testlerde `processing_time_ms`
değerinin (~501ms), en yavaş tekil modülün (port taraması, 500ms timeout)
süresine eşit çıkmasıyla doğrulanmıştır — sıralı çalışsaydı bu süre
1.5-2 saniyeye yakın olurdu.

### 3. IP Validation ve Girdi Doğrulama

Tüm girdi doğrulaması, herhangi bir modüle ulaşmadan ÖNCE, handler
girişinde tek bir yerde yapılır (fail-fast prensibi):

- E-posta formatı `net/mail.ParseAddress` ile doğrulanır.
- IP adresi `net.ParseIP` ile doğrulanır; geçersiz bir IP (örn.
  `999.999.999.999`) **400 Bad Request** ile anında reddedilir. (İlk
  sürümde bu kontrol eksikti ve geçersiz IP'ler port tarama modülüne
  kadar sızıp `valid_ip:false` ile sessizce 200 OK dönüyordu — bu,
  kullanıcı testleriyle tespit edilip düzeltilmiştir.)
- JSON gövdesi `json.Decoder.DisallowUnknownFields()` ile katı şekilde
  ayrıştırılır; tanımsız bir alan (örn. `"hacker":"yes"`) isteği
  reddeder — bu, API sözleşmesinin (contract) sessizce genişlemesini
  ve olası kafa karıştırıcı davranışları önler.

### 4. Rate Limiting

`internal/handler/ratelimit.go`, harici hiçbir bağımlılık kullanmadan
(yalnızca stdlib `sync`/`time`/`net`) IP bazlı bir **token bucket** rate
limiter uygular:

- **Limit:** IP başına dakikada 60 istek (saniyede 1 token dolum hızı,
  60 token'lık burst kapasitesi).
- **Neden token bucket, neden sabit pencere (fixed window) değil:** Sabit
  pencere sayaçları, pencere sınırında (örn. dakikanın son saniyesi +
  yeni dakikanın ilk saniyesi) iki katı isteğe izin verebilir. Token
  bucket bu sorunu yaşamaz ve sürekli, öngörülebilir bir sınırlama sağlar.
- **İnce taneli kilitleme:** Her IP kendi `visitor` struct'ında kendi
  `sync.Mutex`'ine sahiptir; global bir kilit yerine bu yaklaşım, farklı
  IP'lerin birbirini beklemeden eşzamanlı işlenmesini sağlar.
- **Bellek yönetimi:** 3 dakika boyunca istek göndermeyen IP'lerin kaydı,
  arka planda çalışan bir `cleanup` goroutine'i tarafından otomatik
  temizlenir.
- **Amaç:** TTL cache tek başına *tekrarlanan* isteklere karşı korur,
  ama HER ZAMAN FARKLI email/IP kombinasyonu gönderen bir saldırgana
  (cache-miss DoS) karşı hiçbir koruma sağlamaz — çünkü her istek gerçek
  bir DNS sorgusu + port taraması + Gravatar isteği tetikler. Rate
  limiter, tam olarak bu senaryoya karşı bir "korumacı kalkan" görevi
  görür.
- **Yanıt:** Limit aşıldığında `429 Too Many Requests` + `Retry-After: 60`
  header'ı + açıklayıcı JSON body döner.
- **Not (X-Forwarded-For güvenliği):** `clientIP()` fonksiyonu, varsa
  `X-Forwarded-For` header'ının ilk değerini, yoksa TCP bağlantısının
  gerçek adresini (`r.RemoteAddr`) kullanır. API doğrudan internete
  açıksa (güvenilir bir reverse proxy arkasında değilse), bu header
  istemci tarafından taklit edilebileceğinden dikkatle ele alınmalıdır;
  güvenilir bir proxy/load balancer arkasında konuşlandırıldığında
  güvenlidir.

---

## Performans: v1 → v2 → v3 Karşılaştırması

Aşağıdaki tablo, aynı `hey -n 10000 -c 100` yük testinin (tek endpoint,
`test@gmail.com` / `8.8.8.8`) proje geliştirme sürecindeki üç aşamada
ölçülen sonuçlarını karşılaştırır:

| Metrik | v1 (cache yok) | v2 (DNS + port cache) | v3 (+ Gravatar cache) |
|---|---|---|---|
| Requests/sec | 180.4 | 1.316,6 | 89.004,8 |
| Ortalama gecikme | 539,6 ms | 74,5 ms | 1,0 ms |
| p50 | 501,2 ms | 56,9 ms | 0,7 ms |
| p90 | 503,3 ms | 111,1 ms | 2,2 ms |
| p99 | 3000,9 ms | 304,0 ms | 5,3 ms |
| Toplam süre (10k istek) | 54,17 sn | 7,60 sn | 0,11 sn |
| Hata sayısı | 0 | 0 | 0 |

> ### ⚠️ Kritik Şeffaflık Notu — "Localhost Sentetik Tavan"
>
> **v3'teki 89.004,8 req/s rakamı gerçek bir ölçümdür, ancak üretim
> kapasitesi olarak yorumlanmamalıdır.** Bu sayı, testten hemen önce
> aynı `email`/`ip` kombinasyonuyla ısıtılmış (warm) bir cache üzerinden
> elde edilmiştir; dolayısıyla test sırasında hiçbir gerçek DNS sorgusu,
> TCP port taraması veya Gravatar HTTP isteği yapılmamıştır. Bu durumda
> ölçülen şey artık dolandırıcılık tespiti değil, **Go'nun stdlib HTTP
> sunucusunun + JSON encode/decode'un + `sync.RWMutex` map okumasının
> localhost loopback üzerindeki saf overhead'idir** — yani cache
> katmanının teorik en-iyi-durum (best-case) tavanı.
>
> Farklı (benzersiz) email/IP kombinasyonlarıyla gelen gerçek trafikte
> (cache-miss senaryosu), maliyet gerçek DNS + port taraması + Gravatar
> isteklerinden kaynaklanır ve performans profili v2'deki rakamlara
> (~1.300 rps, ~75ms ortalama) çok daha yakın olacaktır. Ayrıca artık
> devrede olan **IP bazlı rate limiter (60 istek/dk)**, gerçek dünyada
> tek bir istemcinin bu tavana zaten ulaşmasını engeller — bu limit
> bilinçli bir tasarım kararıdır (bkz. [Rate Limiting](#4-rate-limiting)).
>
> Bu rakamları raporlarken/paylaşırken her zaman **hangi senaryoyu
> (cache-hit vs. cache-miss) ve hangi modu (realistic vs. raw) ölçtüğünüzü
> açıkça belirtin.** Bkz. aşağıdaki [Benchmark Aracı](#benchmark-aracı) bölümü.

---

## Benchmark Aracı

`scripts/benchmark.go`, yukarıdaki dürüstlük ilkesini otomatikleştiren,
projeye dahil bağımsız bir CLI aracıdır. Hem **cache-hit** hem
**cache-miss** senaryolarını, rate limiter'ı hesaba katarak iki ayrı
modda ölçer:

```bash
# API'yi ayrı bir terminalde çalıştırın: go run .

# Realistic mod (varsayılan): tek istemci IP'si simüle edilir,
# rate limiter AKTİFTİR — 60 istekten sonra 429'lar beklenir.
go run ./scripts -n 300 -c 20 -mode realistic

# Raw mod: her istek farklı bir X-Forwarded-For ile gönderilir,
# rate limiter'ı KASITLI olarak by-pass eder; yalnızca sunucunun/cache
# katmanının HAM teorik kapasitesini (kapasite planlaması amaçlı) ölçer.
go run ./scripts -n 5000 -c 100 -mode raw
```

Çıktı, her iki senaryo (`cache-hit` / `cache-miss`) için ayrı ayrı
`Başarılı`, `429`, `Hata`, `RPS`, `p50`, `p99` sütunlarını ve altında
bu sayıların nasıl yorumlanması gerektiğini açıklayan bir rehber içerir.
Araç bilinçli olarak tek bir "büyük rakam" üretmez; her zaman hangi
koşullar altında ölçüldüğünü etiketler.

---

## Risk Skorlama Ağırlıkları

| Modül | Katkı |
|---|---|
| Typo-squat şüphesi (benzerlik >= %90, birebir değil) | +45 |
| MX kaydı yok | +30 |
| SPF kaydı yok | +10 |
| DMARC kaydı yok | +10 |
| Alan adı hiç çözümlenemiyor | =50 (sabit, diğerlerinin yerine geçer) |
| Gravatar profili mevcut | −15 |
| Gravatar profili yok | +5 |
| Bilinen proxy/VPN portu (1080/3128/8080/1194) açık | +35 |
| Disposable (tek kullanımlık) e-posta alan adı | +40 |

Toplam skor 0-100 aralığına sıkıştırılır (clamp).
**Karar (Verdict):** `risk_score >= 70 → BLOCK`, `>= 35 → REVIEW`, aksi halde `ALLOW`.

---

## Docker ile Çalıştırma

`Dockerfile`, iki aşamalı (multi-stage) bir build kullanır:

1. **Builder aşaması** (`golang:1.22-alpine`): Statik, CGO'suz
   (`CGO_ENABLED=0`), sembolleri küçültülmüş (`-ldflags="-s -w"`) bir
   binary derler.
2. **Runtime aşaması** (`gcr.io/distroless/static-debian12:nonroot`):
   İçinde shell, paket yöneticisi veya libc bulunmayan, yalnızca birkaç
   MB'lık minimal bir imaj. Container, root olmayan (`nonroot`, UID
   65532) bir kullanıcıyla çalışır. CA sertifikaları, dış HTTPS
   servislerine (Gravatar, GitHub) erişim için builder aşamasından
   ayrıca kopyalanır (distroless/static bunları içermez).

```bash
docker build -t fraudox-api .
docker run -p 8080:8080 fraudox-api
```

> **Test notu:** Bu Dockerfile, geliştirme sırasında satır satır
> gözden geçirilmiş ve multi-stage/distroless/nonroot en iyi
> pratiklerine göre yazılmıştır; ancak geliştirme ortamının ağ
> kısıtlamaları nedeniyle `docker build` bizzat bu ortamda **çalıştırılıp
> doğrulanamamıştır**. Kendi ortamınızda build almanızı ve
> `docker run` sonrası `curl http://localhost:8080/healthz` ile
> doğrulamanızı öneririz.

---

## Değişiklik Geçmişi

Gerçek `curl` testleri ve `hey` yük testleriyle (10.000 istek, 100
eşzamanlılık) tespit edilip düzeltilen sorunlar, kronolojik sırayla:

1. **Geçersiz IP artık 400 döndürüyor.** Önceden geçersiz bir IP, port
   tarama modülüne kadar sızıp sessizce 200 OK dönüyordu. Artık
   `net.ParseIP` doğrulaması handler girişinde yapılıyor.
2. **DNS sonuç alanları netleştirildi.** `domain_resolvable` artık MX
   sorgusundan tamamen bağımsız, ayrı bir A/AAAA sorgusuna dayanıyor;
   MX'e özel hata (`mx_lookup_error`) ve genel çözümlenemezlik hatası
   (`resolve_error`) ayrı alanlarda tutuluyor.
3. **DNS sonuçları önbelleğe alınıyor** (5 dakika TTL, domain bazlı).
4. **Port tarama sonuçları önbelleğe alınıyor** (5 dakika TTL, IP bazlı).
   Aynı domain/IP'ye ikinci istek `501ms → 3ms`'ye düştü;
   `hey -n 10000 -c 100` testinde toplam süre `54,17s → 7,60s`.
5. **Gravatar sonuçları önbelleğe alınıyor** (1 saat TTL, email MD5
   hash'i bazlı). Yalnızca kesin sonuçlar (HTTP 200/404) cache'lenir.
   `hey` testinde requests/sec `1.316,6 → 89.004,8`'e çıktı — ancak bu
   rakamın tamamen ısınmış cache üzerinden ölçüldüğü ve gerçek üretim
   kapasitesini temsil etmediği ayrıca belgelendi (bkz.
   [Kritik Şeffaflık Notu](#️-kritik-şeffaflık-notu--localhost-sentetik-tavan)).
6. **IP bazlı rate limiting eklendi** (dakikada 60 istek/IP, token
   bucket algoritması), cache-miss senaryolarıyla yapılabilecek DoS/
   kaynak tüketimi saldırılarına karşı.
7. **Dürüst, iki-modlu benchmark aracı eklendi** (`scripts/benchmark.go`),
   cache-hit ve cache-miss senaryolarını rate limiter'ı hesaba katarak
   ayrı ayrı, açıkça etiketlenmiş şekilde raporluyor.
8. **Multi-stage, distroless Dockerfile eklendi**, üretim dağıtımı için.

## Notlar

- Hiçbir ücretli/API-key gerektiren üçüncü parti servis kullanılmaz.
  Gravatar ve GitHub raw içerik indirme uçları kimlik doğrulama
  gerektirmeyen, herkese açık ve ücretsiz servislerdir.
- `net.DefaultResolver` (Go stdlib) DNS sorguları için, `net.DialTimeout`
  port taraması için kullanılır.
- Disposable liste kaynakları: `disposable-email-domains/disposable-email-domains`
  ve `martenson/disposable-email-domains` GitHub repoları (raw blocklist dosyaları).
