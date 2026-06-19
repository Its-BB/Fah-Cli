package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"fahscan/internal/detector"
	"fahscan/internal/fingerprint"
	"fahscan/pkg/types"
)

type Options struct {
	MaxConcurrency  int
	ConnectTimeout  time.Duration
	BannerTimeout   time.Duration
	HTTPTimeout     time.Duration
	TLSTimeout      time.Duration
	SaveRawEvidence bool
}

type Result struct {
	Services []types.Service
	Findings []types.Finding
}

func Run(ctx context.Context, target string, ports []int, opts Options) Result {
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 25
	}
	jobs := make(chan int)
	var mu sync.Mutex
	result := Result{}
	var wg sync.WaitGroup
	for i := 0; i < opts.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if Open(ctx, target, port, opts.ConnectTimeout) {
					service, findings := detector.Detect(ctx, target, port, detector.Options{BannerTimeout: opts.BannerTimeout, HTTPTimeout: opts.HTTPTimeout, TLSTimeout: opts.TLSTimeout})
					fingerprint.Apply(&service)
					if !opts.SaveRawEvidence {
						service.Banner = ""
					}
					mu.Lock()
					result.Services = append(result.Services, service)
					result.Findings = append(result.Findings, findings...)
					mu.Unlock()
				}
			}
		}()
	}
	for _, port := range ports {
		select {
		case <-ctx.Done():
			break
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].Port < result.Services[j].Port })
	return result
}

func Open(ctx context.Context, target string, port int, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
