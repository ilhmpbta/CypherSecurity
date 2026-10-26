package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type clientBucket struct {
	mu         sync.Mutex
	tokens     float64
	lastUpdate time.Time
	lastSeen   time.Time
}

// RateLimit throttles requests per client IP using a token bucket with opportunistic GC.
func RateLimit(rate float64, burst int) func(http.Handler) http.Handler {
	var (
		mu      sync.Mutex
		clients = make(map[string]*clientBucket)
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			if host == "" {
				host = "unknown"
			}

			now := time.Now()

			mu.Lock()
			// Opportunistic GC if map is large
			if len(clients) > 1000 {
				for k, b := range clients {
					if now.Sub(b.lastSeen) > 5*time.Minute {
						delete(clients, k)
					}
				}
			}

			b, exists := clients[host]
			if !exists {
				b = &clientBucket{
					tokens:     float64(burst),
					lastUpdate: now,
					lastSeen:   now,
				}
				clients[host] = b
			}
			b.lastSeen = now
			mu.Unlock()

			b.mu.Lock()
			elapsed := now.Sub(b.lastUpdate).Seconds()
			b.lastUpdate = now
			b.tokens += elapsed * rate
			if b.tokens > float64(burst) {
				b.tokens = float64(burst)
			}

			if b.tokens < 1.0 {
				b.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}

			b.tokens -= 1.0
			b.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
