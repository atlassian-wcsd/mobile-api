package security

import (
	"net/http"
	"time"
)

// RateLimiter is a simple rate limiter to prevent brute force attacks.
type RateLimiter struct {
	requests map[string]int
	resetTime time.Duration
}

// NewRateLimiter creates a new RateLimiter with a specified reset time.
func NewRateLimiter(resetTime time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string]int),
		resetTime: resetTime,
	}
}

// Allow checks if a request from a given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	if count, exists := rl.requests[ip]; exists {
		if count >= 5 { // limit to 5 requests
			return false
		}
		rl.requests[ip]++
	} else {
		rl.requests[ip] = 1
	}
	return true
}

// Reset clears the request counts after the reset time.
func (rl *RateLimiter) Reset() {
	for {
		time.Sleep(rl.resetTime)
		rl.requests = make(map[string]int)
	}
}

// Middleware to use the rate limiter in an HTTP handler.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !rl.Allow(ip) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}