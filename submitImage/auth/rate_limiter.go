package auth

import (
	"sync"
	"time"
)

type RateLimiter struct {
	attempts map[string]*RateLimit
	mu       sync.RWMutex
}

type RateLimit struct {
	Count     int
	Timestamp time.Time
}

const (
	maxAttempts = 5
	windowSize  = 15 * time.Minute
)

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string]*RateLimit),
	}
}

func (rl *RateLimiter) IsLimited(key string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	limit, exists := rl.attempts[key]
	if !exists {
		return false
	}

	// Reset if window has expired
	if time.Since(limit.Timestamp) > windowSize {
		delete(rl.attempts, key)
		return false
	}

	return limit.Count >= maxAttempts
}

func (rl *RateLimiter) RecordAttempt(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	limit, exists := rl.attempts[key]

	if !exists {
		rl.attempts[key] = &RateLimit{
			Count:     1,
			Timestamp: now,
		}
		return
	}

	// Reset if window has expired
	if time.Since(limit.Timestamp) > windowSize {
		rl.attempts[key] = &RateLimit{
			Count:     1,
			Timestamp: now,
		}
		return
	}

	limit.Count++
}

func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, key)
}