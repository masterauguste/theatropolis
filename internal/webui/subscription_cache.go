package webui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/masterauguste/theatropolis/internal/subscription"
)

const (
	publicRuleSetRequestsPerMinute = 120
	publicRuleSetGlobalPerMinute   = 1200
	publicRuleSetCacheEntries      = 128
	publicRuleSetCacheBytes        = 64 << 20
	renderedSubscriptionEntries    = 256
	renderedSubscriptionBytes      = 32 << 20
)

type fixedWindowLimiter struct {
	mu      sync.Mutex
	entries map[string]fixedWindowEntry
	limit   int
	window  time.Duration
}

type fixedWindowEntry struct {
	started time.Time
	count   int
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{entries: make(map[string]fixedWindowEntry), limit: limit, window: window}
}

func (limiter *fixedWindowLimiter) allow(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	entry := limiter.entries[key]
	if entry.started.IsZero() || now.Sub(entry.started) >= limiter.window || now.Before(entry.started) {
		entry = fixedWindowEntry{started: now, count: 1}
		limiter.entries[key] = entry
		limiter.pruneLocked(now)
		return true
	}
	if entry.count >= limiter.limit {
		return false
	}
	entry.count++
	limiter.entries[key] = entry
	return true
}

func (limiter *fixedWindowLimiter) pruneLocked(now time.Time) {
	if len(limiter.entries) <= 4096 {
		return
	}
	for key, entry := range limiter.entries {
		if now.Sub(entry.started) >= limiter.window {
			delete(limiter.entries, key)
		}
	}
}

type ruleSetCache struct {
	mu       sync.Mutex
	entries  map[string]ruleSetCacheEntry
	inflight map[string]*ruleSetFetch
	total    int
	sema     chan struct{}
}

type ruleSetCacheEntry struct {
	content    []byte
	status     int
	freshUntil time.Time
	staleUntil time.Time
	usedAt     time.Time
}

type ruleSetFetch struct {
	done    chan struct{}
	content []byte
	status  int
	err     error
}

func newRuleSetCache() *ruleSetCache {
	return &ruleSetCache{
		entries: make(map[string]ruleSetCacheEntry), inflight: make(map[string]*ruleSetFetch), sema: make(chan struct{}, 4),
	}
}

func (cache *ruleSetCache) get(
	ctx context.Context,
	key string,
	now time.Time,
	fetch func(context.Context) ([]byte, int, error),
) ([]byte, int, error) {
	cache.mu.Lock()
	entry, exists := cache.entries[key]
	if exists && now.Before(entry.freshUntil) {
		entry.usedAt = now
		cache.entries[key] = entry
		content := append([]byte(nil), entry.content...)
		cache.mu.Unlock()
		return content, entry.status, nil
	}
	if call := cache.inflight[key]; call != nil {
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-call.done:
			return append([]byte(nil), call.content...), call.status, call.err
		}
	}
	call := &ruleSetFetch{done: make(chan struct{})}
	cache.inflight[key] = call
	cache.mu.Unlock()

	fetchContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	select {
	case cache.sema <- struct{}{}:
		call.content, call.status, call.err = fetch(fetchContext)
		<-cache.sema
	case <-fetchContext.Done():
		call.err = fetchContext.Err()
	}

	cache.mu.Lock()
	delete(cache.inflight, key)
	if call.err == nil && (call.status == 200 || call.status == 404) {
		freshFor := time.Hour
		if call.status == 404 {
			freshFor = 10 * time.Minute
		}
		cache.putLocked(key, ruleSetCacheEntry{
			content: append([]byte(nil), call.content...), status: call.status,
			freshUntil: now.Add(freshFor), staleUntil: now.Add(24 * time.Hour), usedAt: now,
		})
	} else if exists && now.Before(entry.staleUntil) {
		call.content, call.status, call.err = append([]byte(nil), entry.content...), entry.status, nil
		entry.usedAt = now
		cache.entries[key] = entry
	}
	close(call.done)
	cache.mu.Unlock()
	return append([]byte(nil), call.content...), call.status, call.err
}

func (cache *ruleSetCache) putLocked(key string, entry ruleSetCacheEntry) {
	if old, exists := cache.entries[key]; exists {
		cache.total -= len(old.content)
	}
	cache.entries[key] = entry
	cache.total += len(entry.content)
	for len(cache.entries) > publicRuleSetCacheEntries || cache.total > publicRuleSetCacheBytes {
		oldestKey := ""
		var oldest time.Time
		for candidate, value := range cache.entries {
			if candidate == key && len(cache.entries) > 1 {
				continue
			}
			if oldestKey == "" || value.usedAt.Before(oldest) {
				oldestKey, oldest = candidate, value.usedAt
			}
		}
		if oldestKey == "" {
			break
		}
		cache.total -= len(cache.entries[oldestKey].content)
		delete(cache.entries, oldestKey)
	}
}

type renderedSubscriptionCache struct {
	mu      sync.Mutex
	entries map[string]renderedSubscriptionEntry
	total   int
}

type renderedSubscriptionEntry struct {
	content     []byte
	contentType string
	usedAt      time.Time
}

func newRenderedSubscriptionCache() *renderedSubscriptionCache {
	return &renderedSubscriptionCache{entries: make(map[string]renderedSubscriptionEntry)}
}

func (cache *renderedSubscriptionCache) render(format subscription.Format, profile subscription.Profile, now time.Time) ([]byte, string, error) {
	encoded, err := json.Marshal(profile)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(append([]byte(format+"\x00"), encoded...))
	key := string(digest[:])
	cache.mu.Lock()
	if entry, exists := cache.entries[key]; exists {
		entry.usedAt = now
		cache.entries[key] = entry
		content := append([]byte(nil), entry.content...)
		cache.mu.Unlock()
		return content, entry.contentType, nil
	}
	cache.mu.Unlock()

	content, contentType, err := subscription.Render(format, profile)
	if err != nil {
		return nil, "", err
	}
	if len(content) > renderedSubscriptionBytes {
		return content, contentType, nil
	}
	cache.mu.Lock()
	cache.entries[key] = renderedSubscriptionEntry{content: append([]byte(nil), content...), contentType: contentType, usedAt: now}
	cache.total += len(content)
	for len(cache.entries) > renderedSubscriptionEntries || cache.total > renderedSubscriptionBytes {
		oldestKey := ""
		var oldest time.Time
		for candidate, value := range cache.entries {
			if candidate == key && len(cache.entries) > 1 {
				continue
			}
			if oldestKey == "" || value.usedAt.Before(oldest) {
				oldestKey, oldest = candidate, value.usedAt
			}
		}
		if oldestKey == "" {
			break
		}
		cache.total -= len(cache.entries[oldestKey].content)
		delete(cache.entries, oldestKey)
	}
	cache.mu.Unlock()
	return content, contentType, nil
}

var errRuleSetUnavailable = errors.New("rule set is unavailable")
