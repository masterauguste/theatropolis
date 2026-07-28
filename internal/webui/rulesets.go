package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	ruleSetCatalogTTL      = time.Hour
	maxRuleSetResponseSize = 4 << 20
)

// RuleSetOptions lists available geo rule-set names (e.g. "openai", "cn")
// for the configuration editor.
type RuleSetOptions interface {
	Options(context.Context) ([]string, error)
}

// RuleSetCatalog discovers rule-set names through the GitHub REST API git
// trees endpoint. Rule-set data is near-static, so results are cached for
// ruleSetCatalogTTL, which keeps unauthenticated usage well below GitHub's
// 60 requests per hour rate limit.
type RuleSetCatalog struct {
	client      *http.Client
	now         func() time.Time
	mu          sync.Mutex
	cached      []string
	expiresAt   time.Time
	treeURL     string
	namePattern *regexp.Regexp
}

func NewGeositeRuleSetCatalog(client *http.Client) *RuleSetCatalog {
	catalog := newRuleSetCatalog(client)
	catalog.treeURL = "https://api.github.com/repos/SagerNet/sing-geosite/git/trees/rule-set"
	catalog.namePattern = regexp.MustCompile(`^geosite-(.+)\.srs$`)
	return catalog
}

func NewGeoipRuleSetCatalog(client *http.Client) *RuleSetCatalog {
	catalog := newRuleSetCatalog(client)
	catalog.treeURL = "https://api.github.com/repos/SagerNet/sing-geoip/git/trees/rule-set"
	catalog.namePattern = regexp.MustCompile(`^geoip-(.+)\.srs$`)
	return catalog
}

func newRuleSetCatalog(client *http.Client) *RuleSetCatalog {
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
		client: client,
		now:    time.Now,
	}
}

func (c *RuleSetCatalog) Options(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	if len(c.cached) != 0 && now.Before(c.expiresAt) {
		return append([]string(nil), c.cached...), nil
	}
	options, err := c.fetch(ctx)
	if err != nil {
		if len(c.cached) != 0 {
			return append([]string(nil), c.cached...), nil
		}
		return nil, err
	}
	c.cached = append([]string(nil), options...)
	c.expiresAt = now.Add(ruleSetCatalogTTL)
	return options, nil
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
