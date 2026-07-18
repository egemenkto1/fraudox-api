package scoring

import (
	"context"
	"net"
)

// netResolverImpl, Go'nun standart "net" paketindeki net.Resolver'ı
// kullanarak gerçek MX ve TXT DNS sorgularını gerçekleştirir.
// Bu ayrım (dns.go'daki wrapper'dan bağımsız dosya), gelecekte mock'lanabilir
// bir arayüz (interface) haline getirilmesini kolaylaştırır.
type netResolverImpl struct{}

// lookupMX, verilen alan adı için MX kayıtlarını çözümler ve
// öncelik (preference) sırasına göre "host" değerlerini string dizisi olarak döner.
func (netResolverImpl) lookupMX(ctx context.Context, domain string) ([]string, error) {
	resolver := net.DefaultResolver
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(mxRecords))
	for _, mx := range mxRecords {
		hosts = append(hosts, mx.Host)
	}
	return hosts, nil
}

// lookupTXT, verilen alan adı (veya alt alan adı) için TXT kayıtlarını
// çözümler. SPF ve DMARC kontrolleri bu fonksiyon üzerinden yapılır.
func (netResolverImpl) lookupTXT(ctx context.Context, domain string) ([]string, error) {
	resolver := net.DefaultResolver
	return resolver.LookupTXT(ctx, domain)
}

// lookupHost, alan adının DNS'te genel olarak var olup olmadığını
// (A/AAAA kaydı) MX/TXT sorgularından tamamen bağımsız olarak kontrol
// eder. Bu, "alan adı hiç yok" ile "alan adı var ama MX kaydı yok"
// durumlarını kesin biçimde ayırmak için kullanılır.
func (netResolverImpl) lookupHost(ctx context.Context, domain string) ([]string, error) {
	resolver := net.DefaultResolver
	return resolver.LookupHost(ctx, domain)
}
