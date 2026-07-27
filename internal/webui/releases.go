package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
)

const (
	releaseCatalogTTL          = 10 * time.Minute
	maxReleaseResponseSize     = 2 << 20
	maxReleaseResponseSizeWide = 4 << 20
	maxReleasePages            = 40
)

type AgentRelease struct {
	Tag         string
	Prerelease  bool
	PublishedAt time.Time
}

type ReleaseCatalog interface {
	Versions(context.Context) ([]AgentRelease, error)
}

type GitHubReleaseCatalog struct {
	client          *http.Client
	now             func() time.Time
	mu              sync.Mutex
	cached          []AgentRelease
	expiresAt       time.Time
	apiURL          string
	validVersion    func(string) bool
	perPage         int
	maxResponseSize int64
}

func NewGitHubReleaseCatalog(client *http.Client) *GitHubReleaseCatalog {
	if client == nil {
		client = &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(request *http.Request, _ []*http.Request) error {
				if request.URL.Scheme != "https" ||
					request.URL.Hostname() != "api.github.com" {
					return errors.New("GitHub release catalog redirected to an untrusted host")
				}
				return nil
			},
		}
	}
	return &GitHubReleaseCatalog{
		client:          client,
		now:             time.Now,
		apiURL:          "https://api.github.com/repos/masterauguste/theatropolis/releases",
		validVersion:    agentupdate.ValidVersion,
		perPage:         100,
		maxResponseSize: maxReleaseResponseSize,
	}
}

func NewSingBoxReleaseCatalog(client *http.Client) *GitHubReleaseCatalog {
	catalog := NewGitHubReleaseCatalog(client)
	catalog.apiURL = "https://api.github.com/repos/SagerNet/sing-box/releases"
	catalog.validVersion = singboxupdate.ValidVersion
	catalog.perPage = 3
	catalog.maxResponseSize = maxReleaseResponseSizeWide
	return catalog
}

func (c *GitHubReleaseCatalog) Versions(ctx context.Context) ([]AgentRelease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	if len(c.cached) != 0 && now.Before(c.expiresAt) {
		return append([]AgentRelease(nil), c.cached...), nil
	}
	releases, err := c.fetch(ctx)
	if err != nil {
		if len(c.cached) != 0 {
			return append([]AgentRelease(nil), c.cached...), nil
		}
		return nil, err
	}
	c.cached = append([]AgentRelease(nil), releases...)
	c.expiresAt = now.Add(releaseCatalogTTL)
	return releases, nil
}

func (c *GitHubReleaseCatalog) fetch(ctx context.Context) ([]AgentRelease, error) {
	releases := make([]AgentRelease, 0, 32)
	for page := 1; page <= maxReleasePages; page++ {
		endpoint := fmt.Sprintf(
			"%s?per_page=%d&page=%d",
			c.apiURL,
			c.perPage,
			page,
		)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		response, err := c.client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("fetch GitHub releases: %w", err)
		}
		pageReleases, decodeErr := decodeReleasePage(response, c.maxResponseSize)
		response.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		for _, release := range pageReleases {
			if release.Draft || !c.validVersion(release.TagName) {
				continue
			}
			releases = append(releases, AgentRelease{
				Tag:         release.TagName,
				Prerelease:  release.Prerelease,
				PublishedAt: release.PublishedAt.UTC(),
			})
		}
		if len(pageReleases) < c.perPage {
			break
		}
	}
	sort.SliceStable(releases, func(left, right int) bool {
		return releases[left].PublishedAt.After(releases[right].PublishedAt)
	})
	return releases, nil
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
}

func decodeReleasePage(response *http.Response, maxBytes int64) ([]githubRelease, error) {
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"GitHub releases returned status %d",
			response.StatusCode,
		)
	}
	if response.ContentLength > maxBytes {
		return nil, errors.New("GitHub releases response exceeds the size limit")
	}
	decoder := json.NewDecoder(io.LimitReader(
		response.Body,
		maxBytes+1,
	))
	decoder.DisallowUnknownFields()
	// GitHub adds fields over time, so decode through raw objects and then
	// select only the small trusted subset this UI needs.
	var raw []map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode GitHub releases: %w", err)
	}
	releases := make([]githubRelease, 0, len(raw))
	for _, item := range raw {
		var release githubRelease
		for name, destination := range map[string]any{
			"tag_name":     &release.TagName,
			"draft":        &release.Draft,
			"prerelease":   &release.Prerelease,
			"published_at": &release.PublishedAt,
		} {
			value, exists := item[name]
			if !exists || string(value) == "null" {
				continue
			}
			if err := json.Unmarshal(value, destination); err != nil {
				return nil, fmt.Errorf("decode GitHub release field %s: %w", name, err)
			}
		}
		releases = append(releases, release)
	}
	return releases, nil
}
