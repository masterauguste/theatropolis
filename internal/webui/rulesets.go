package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	ruleSetCatalogTTL          = 24 * time.Hour
	ruleSetCatalogPollInterval = time.Hour
	maxRuleSetResponseSize     = 4 << 20
)

// RuleSetOptions lists available geo rule-set names (e.g. "openai", "cn")
// for the configuration editor.
type RuleSetOptions interface {
	Options(context.Context) ([]string, error)
}

// RuleSetCatalog discovers rule-set names through the GitHub REST API git
// trees endpoint. The last good catalog can be persisted so editor searches
// never wait on GitHub after a master restart or during an upstream outage.
type RuleSetCatalog struct {
	client      *http.Client
	now         func() time.Time
	mu          sync.Mutex
	fetchMu     sync.Mutex
	cached      []string
	expiresAt   time.Time
	cachePath   string
	refreshing  bool
	treeURL     string
	namePattern *regexp.Regexp
}

type ruleSetCacheDocument struct {
	UpdatedAt time.Time `json:"updated_at"`
	Options   []string  `json:"options"`
}

func NewGeositeRuleSetCatalog(client *http.Client, cachePath ...string) *RuleSetCatalog {
	catalog := newRuleSetCatalog(client, firstPath(cachePath))
	catalog.treeURL = "https://api.github.com/repos/SagerNet/sing-geosite/git/trees/rule-set"
	catalog.namePattern = regexp.MustCompile(`^geosite-(.+)\.srs$`)
	catalog.loadCache()
	return catalog
}

func NewGeoipRuleSetCatalog(client *http.Client, cachePath ...string) *RuleSetCatalog {
	catalog := newRuleSetCatalog(client, firstPath(cachePath))
	catalog.treeURL = "https://api.github.com/repos/SagerNet/sing-geoip/git/trees/rule-set"
	catalog.namePattern = regexp.MustCompile(`^geoip-(.+)\.srs$`)
	catalog.loadCache()
	return catalog
}

func firstPath(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

func newRuleSetCatalog(client *http.Client, cachePath string) *RuleSetCatalog {
	if client == nil {
		client = &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(request *http.Request, _ []*http.Request) error {
				if request.URL.Scheme != "https" || request.URL.Hostname() != "api.github.com" {
					return errors.New("rule-set catalog redirected to an untrusted host")
				}
				return nil
			},
		}
	}
	return &RuleSetCatalog{
		client:    client,
		now:       time.Now,
		cachePath: cachePath,
	}
}

func (c *RuleSetCatalog) Options(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	now := c.now().UTC()
	if len(c.cached) != 0 && now.Before(c.expiresAt) {
		options := append([]string(nil), c.cached...)
		c.mu.Unlock()
		return options, nil
	}
	if len(c.cached) != 0 {
		options := append([]string(nil), c.cached...)
		refresh := !c.refreshing
		c.refreshing = true
		c.mu.Unlock()
		if refresh {
			go func() {
				c.refreshWithTimeout()
				c.mu.Lock()
				c.refreshing = false
				c.mu.Unlock()
			}()
		}
		return options, nil
	}
	c.mu.Unlock()
	return c.refresh(ctx)
}

// Start refreshes a stale disk cache at startup and every catalog TTL. A
// failed refresh leaves the last good copy available indefinitely.
func (c *RuleSetCatalog) Start(ctx context.Context) {
	go func() {
		c.refreshWithTimeout()
		ticker := time.NewTicker(ruleSetCatalogPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.refreshWithTimeout()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *RuleSetCatalog) refreshWithTimeout() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = c.refresh(ctx)
}

func (c *RuleSetCatalog) refresh(ctx context.Context) ([]string, error) {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	c.mu.Lock()
	now := c.now().UTC()
	if len(c.cached) != 0 && now.Before(c.expiresAt) {
		options := append([]string(nil), c.cached...)
		c.mu.Unlock()
		return options, nil
	}
	c.mu.Unlock()
	options, err := c.fetch(ctx)
	if err != nil {
		c.mu.Lock()
		if len(c.cached) != 0 {
			options := append([]string(nil), c.cached...)
			c.mu.Unlock()
			return options, nil
		}
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.cached = append([]string(nil), options...)
	c.expiresAt = now.Add(ruleSetCatalogTTL)
	c.mu.Unlock()
	_ = c.persistCache(ruleSetCacheDocument{
		UpdatedAt: now,
		Options:   options,
	})
	return options, nil
}

func (c *RuleSetCatalog) loadCache() {
	if c.cachePath == "" {
		return
	}
	info, err := os.Lstat(c.cachePath)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > maxRuleSetResponseSize {
		return
	}
	encoded, err := os.ReadFile(c.cachePath)
	if err != nil {
		return
	}
	var document ruleSetCacheDocument
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return
	}
	if document.UpdatedAt.IsZero() || len(document.Options) == 0 {
		return
	}
	for _, option := range document.Options {
		if option == "" || len(option) > 512 || strings.TrimSpace(option) != option {
			return
		}
	}
	c.cached = append([]string(nil), document.Options...)
	c.expiresAt = document.UpdatedAt.UTC().Add(ruleSetCatalogTTL)
}

func (c *RuleSetCatalog) persistCache(document ruleSetCacheDocument) error {
	if c.cachePath == "" {
		return nil
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode rule-set cache: %w", err)
	}
	directory := filepath.Dir(c.cachePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create rule-set cache directory: %w", err)
	}
	if info, err := os.Lstat(c.cachePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("rule-set cache path is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect rule-set cache: %w", err)
	}
	temp, err := os.CreateTemp(directory, "."+filepath.Base(c.cachePath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary rule-set cache: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure rule-set cache: %w", err)
	}
	if _, err := temp.Write(encoded); err != nil {
		return fmt.Errorf("write rule-set cache: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync rule-set cache: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close rule-set cache: %w", err)
	}
	if err := os.Rename(tempPath, c.cachePath); err != nil {
		return fmt.Errorf("replace rule-set cache: %w", err)
	}
	committed = true
	return nil
}

func (c *RuleSetCatalog) fetch(ctx context.Context) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.treeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare rule-set discovery: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "theatropolis-master")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request GitHub rule-set tree: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub rule-set discovery returned status %d", response.StatusCode)
	}
	if response.ContentLength > maxRuleSetResponseSize {
		return nil, errors.New("GitHub rule-set response exceeds the size limit")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxRuleSetResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub rule-set tree: %w", err)
	}
	if len(encoded) > maxRuleSetResponseSize {
		return nil, errors.New("GitHub rule-set response exceeds the size limit")
	}

	var tree struct {
		Entries []struct {
			Path string `json:"path"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(encoded, &tree); err != nil {
		return nil, fmt.Errorf("decode GitHub rule-set tree: %w", err)
	}
	if tree.Truncated {
		return nil, errors.New("GitHub rule-set tree is truncated")
	}

	unique := make(map[string]struct{})
	options := make([]string, 0, len(tree.Entries))
	for _, entry := range tree.Entries {
		match := c.namePattern.FindStringSubmatch(entry.Path)
		if match == nil {
			continue
		}
		name := match[1]
		if _, exists := unique[name]; exists {
			continue
		}
		unique[name] = struct{}{}
		options = append(options, name)
	}
	if len(options) == 0 {
		return nil, errors.New("GitHub returned no rule-set names")
	}
	sort.Strings(options)
	return options, nil
}

func ruleSetDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, err.Error())
	clean = strings.TrimSpace(clean)
	if len(clean) > 300 {
		clean = clean[:300] + "..."
	}
	return "Rule-set lookup failed: " + clean
}
