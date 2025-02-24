package security

import (
    "time"
    "golang.org/x/time/rate"
    "sync"
)

type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.Mutex
    r        rate.Limit
    b        int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        r:        r,
        b:        b,
    }
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    limiter, exists := rl.limiters[key]
    if !exists {
        limiter = rate.NewLimiter(rl.r, rl.b)
        rl.limiters[key] = limiter
    }

    return limiter
}

func (rl *RateLimiter) Allow(key string) bool {
    limiter := rl.getLimiter(key)
    return limiter.Allow()
}

func (rl *RateLimiter) CleanupExpiredEntries(expiration time.Duration) {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    for key, limiter := range rl.limiters {
        if time.Since(limiter.Reserve().Delay()) > expiration {
            delete(rl.limiters, key)
        }
    }
}
