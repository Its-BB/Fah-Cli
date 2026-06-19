package detector

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"fahscan/pkg/types"
	"github.com/PuerkitoBio/goquery"
)

type Options struct {
	BannerTimeout time.Duration
	HTTPTimeout   time.Duration
	TLSTimeout    time.Duration
}

func Detect(ctx context.Context, target string, port int, opts Options) (types.Service, []types.Finding) {
	service := types.Service{
		Port:      port,
		Protocol:  "tcp",
		Service:   inferService(port),
		Metadata:  map[string]string{},
		CreatedAt: time.Now(),
	}
	banner := GrabBanner(ctx, target, port, opts.BannerTimeout)
	service.Banner = banner
	fillFromBanner(&service, banner)
	var findings []types.Finding
	if isHTTPPort(port, service.Service) {
		httpService, httpFindings := HTTP(ctx, target, port, false, opts.HTTPTimeout)
		mergeService(&service, httpService)
		findings = append(findings, httpFindings...)
	}
	if isHTTPSPort(port, service.Service) {
		httpService, httpFindings := HTTP(ctx, target, port, true, opts.HTTPTimeout)
		mergeService(&service, httpService)
		findings = append(findings, httpFindings...)
		tlsMeta, tlsFindings := TLS(target, port, opts.TLSTimeout)
		for k, v := range tlsMeta {
			service.Metadata[k] = v
		}
		findings = append(findings, tlsFindings...)
	}
	return service, findings
}

func GrabBanner(ctx context.Context, target string, port int, timeout time.Duration) string {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, fmt.Sprint(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if port == 80 || port == 8080 || port == 8081 {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: fahscan\r\n\r\n", target)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func HTTP(ctx context.Context, target string, port int, tlsMode bool, timeout time.Duration) (types.Service, []types.Finding) {
	scheme := "http"
	if tlsMode {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(target, fmt.Sprint(port)))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "fahscan")
	client := &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	if tlsMode {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{ServerName: target, MinVersion: tls.VersionTLS12}}
	}
	service := types.Service{Port: port, Protocol: scheme, Service: scheme, Metadata: map[string]string{}, CreatedAt: time.Now()}
	resp, err := client.Do(req)
	if err != nil {
		return service, nil
	}
	defer resp.Body.Close()
	service.Metadata["status_code"] = fmt.Sprint(resp.StatusCode)
	copyHeader := func(key, meta string) {
		if val := resp.Header.Get(key); val != "" {
			service.Metadata[meta] = val
		}
	}
	copyHeader("Server", "server")
	copyHeader("X-Powered-By", "x_powered_by")
	copyHeader("Content-Type", "content_type")
	copyHeader("Location", "redirect_location")
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	title := strings.TrimSpace(doc.Find("title").First().Text())
	if title != "" {
		service.Metadata["title"] = title
	}
	service.Product = firstNonEmpty(resp.Header.Get("Server"), resp.Header.Get("X-Powered-By"))
	findings := HTTPFindings(service, resp.Header, tlsMode)
	return service, findings
}

func HTTPFindings(service types.Service, h http.Header, tlsMode bool) []types.Finding {
	var out []types.Finding
	add := func(title, severity, evidence, rec string) {
		out = append(out, types.Finding{ServiceID: service.ID, Title: title, Severity: severity, Description: title, Evidence: evidence, Recommendation: rec, Confidence: "confirmed", CreatedAt: time.Now()})
	}
	if !tlsMode {
		add("HTTP without TLS", "medium", "The service responded over cleartext HTTP.", "Serve the site over HTTPS and redirect HTTP to HTTPS.")
	}
	headers := map[string]string{
		"Strict-Transport-Security": "missing Strict-Transport-Security",
		"Content-Security-Policy":   "missing Content-Security-Policy",
		"X-Frame-Options":           "missing X-Frame-Options",
		"X-Content-Type-Options":    "missing X-Content-Type-Options",
		"Referrer-Policy":           "missing Referrer-Policy",
		"Permissions-Policy":        "missing Permissions-Policy",
	}
	for key, title := range headers {
		if h.Get(key) == "" {
			add(title, "low", key+" header was absent.", "Set an appropriate "+key+" header.")
		}
	}
	if h.Get("Server") != "" {
		add("exposed Server header", "low", "Server: "+h.Get("Server"), "Remove or minimize server version disclosure.")
	}
	if h.Get("X-Powered-By") != "" {
		add("exposed X-Powered-By header", "low", "X-Powered-By: "+h.Get("X-Powered-By"), "Remove framework version disclosure.")
	}
	title := strings.ToLower(service.Metadata["title"])
	server := strings.ToLower(service.Metadata["server"])
	if strings.Contains(title, "default") || strings.Contains(server, "default") {
		add("possible default page", "info", "Title/header suggests a default page.", "Replace default content with intentional application content.")
	}
	if strings.Contains(title, "index of /") {
		add("possible directory listing", "medium", "Page title suggests directory listing.", "Disable directory indexes unless intentionally public.")
	}
	return out
}

func TLS(target string, port int, timeout time.Duration) (map[string]string, []types.Finding) {
	meta := map[string]string{}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", net.JoinHostPort(target, fmt.Sprint(port)), &tls.Config{ServerName: target, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	if err != nil {
		return meta, nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return meta, nil
	}
	cert := state.PeerCertificates[0]
	meta["tls_subject"] = cert.Subject.String()
	meta["tls_issuer"] = cert.Issuer.String()
	meta["tls_not_before"] = cert.NotBefore.Format(time.RFC3339)
	meta["tls_not_after"] = cert.NotAfter.Format(time.RFC3339)
	meta["tls_dns_names"] = strings.Join(cert.DNSNames, ",")
	var findings []types.Finding
	add := func(title, severity, evidence, rec string) {
		findings = append(findings, types.Finding{Title: title, Severity: severity, Description: title, Evidence: evidence, Recommendation: rec, Confidence: "confirmed", CreatedAt: time.Now()})
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		add("expired certificate", "high", "Certificate expired at "+cert.NotAfter.Format(time.RFC3339), "Renew and deploy a valid certificate.")
	} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		add("certificate expiring within 30 days", "medium", "Certificate expires at "+cert.NotAfter.Format(time.RFC3339), "Renew the certificate before expiry.")
	}
	if cert.Issuer.String() == cert.Subject.String() {
		add("self-signed certificate", "medium", "Issuer and subject are identical.", "Use a certificate issued by a trusted CA.")
	}
	if err := cert.VerifyHostname(target); err != nil {
		add("hostname mismatch", "high", err.Error(), "Use a certificate whose SAN covers the target hostname.")
	}
	return meta, findings
}

func fillFromBanner(service *types.Service, banner string) {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh"):
		service.Service, service.Protocol, service.Product = "ssh", "tcp", banner
	case strings.Contains(lower, "ftp"):
		service.Service, service.Protocol, service.Product = "ftp", "tcp", banner
	case strings.Contains(lower, "smtp"):
		service.Service, service.Protocol, service.Product = "smtp", "tcp", banner
	case strings.Contains(lower, "redis"):
		service.Service, service.Product = "redis", "redis"
	case strings.Contains(lower, "mysql"):
		service.Service, service.Product = "mysql", "mysql"
	case strings.Contains(lower, "postgres"):
		service.Service, service.Product = "postgresql", "postgresql"
	}
}

func mergeService(dst *types.Service, src types.Service) {
	if src.Protocol != "" {
		dst.Protocol = src.Protocol
	}
	if src.Service != "" {
		dst.Service = src.Service
	}
	if src.Product != "" {
		dst.Product = src.Product
	}
	if dst.Metadata == nil {
		dst.Metadata = map[string]string{}
	}
	for k, v := range src.Metadata {
		dst.Metadata[k] = v
	}
}

func isHTTPPort(port int, name string) bool {
	return port == 80 || port == 8080 || port == 8081 || port == 8000 || port == 8008 || port == 8888 || strings.Contains(name, "http") || name == "web" || name == "admin-web"
}

func isHTTPSPort(port int, name string) bool {
	return port == 443 || port == 8443 || port == 9443 || strings.Contains(name, "https")
}

func firstNonEmpty(values ...string) string {
	for _, val := range values {
		if strings.TrimSpace(val) != "" {
			return val
		}
	}
	return ""
}

func inferService(port int) string {
	names := map[int]string{
		21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap",
		443: "https", 465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 1433: "mssql",
		1521: "oracle", 3000: "web", 3306: "mysql", 5000: "web", 5173: "web", 5432: "postgresql",
		5984: "couchdb", 6379: "redis", 7001: "admin-web", 8080: "http", 8081: "http",
		8443: "https", 8888: "admin-web", 9000: "admin-web", 9042: "cassandra", 9200: "elasticsearch",
		9300: "elasticsearch", 9443: "https", 11211: "memcached", 27017: "mongodb",
	}
	if name, ok := names[port]; ok {
		return name
	}
	return "unknown"
}
