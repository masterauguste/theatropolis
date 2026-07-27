package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
)

const (
	releaseCatalogTTL      = 10 * time.Minute
	maxReleaseResponseSize = 2 << 20
)

var gitTagReferencePattern = regexp.MustCompile(`refs/tags/([^\x00\s^]+)`)

type AgentRelease struct {
	Tag         string
	Prerelease  bool
	PublishedAt time.Time
}

type ReleaseCatalog interface {
	Versions(context.Context) ([]AgentRelease, error)
}

// GitHubReleaseCatalog discovers tags through GitHub's public Git transport.
// Unlike the REST API this endpoint is not subject to unauthenticated API rate
// limits and does not include large release asset metadata.
type GitHubReleaseCatalog struct {
	client       *http.Client
	now          func() time.Time
	mu           sync.Mutex
	cached       []AgentRelease
	expiresAt    time.Time
	refsURL      string
	validVersion func(string) bool
}

func NewGitHubReleaseCatalog(client *http.Client) *GitHubReleaseCatalog {
	if client == nil {
		client = &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(request *http.Request, _ []*http.Request) error {
				if request.URL.Scheme != "https" || request.URL.Hostname() != "github.com" {
					return errors.New("version catalog redirected to an untrusted host")
				}
				return nil
			},
		}
	}
	return &GitHubReleaseCatalog{
		client:       client,
		now:          time.Now,
		refsURL:      "https://github.com/masterauguste/theatropolis.git/info/refs?service=git-upload-pack",
		validVersion: agentupdate.ValidVersion,
	}
}

func NewSingBoxReleaseCatalog(client *http.Client) *GitHubReleaseCatalog {
	catalog := NewGitHubReleaseCatalog(client)
	catalog.refsURL = "https://github.com/SagerNet/sing-box.git/info/refs?service=git-upload-pack"
	catalog.validVersion = singboxupdate.ValidVersion
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.refsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare tag discovery: %w", err)
	}
	request.Header.Set("Accept", "application/x-git-upload-pack-advertisement")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request GitHub tags: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub tag discovery returned status %d", response.StatusCode)
	}
	if response.ContentLength > maxReleaseResponseSize {
		return nil, errors.New("GitHub tag response exceeds the size limit")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxReleaseResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub tags: %w", err)
	}
	if len(encoded) > maxReleaseResponseSize {
		return nil, errors.New("GitHub tag response exceeds the size limit")
	}

	unique := make(map[string]struct{})
	releases := make([]AgentRelease, 0, 32)
	for _, match := range gitTagReferencePattern.FindAllSubmatch(encoded, -1) {
		tag := string(match[1])
		if _, exists := unique[tag]; exists || !c.validVersion(tag) {
			continue
		}
		unique[tag] = struct{}{}
		releases = append(releases, AgentRelease{
			Tag:        tag,
			Prerelease: strings.Contains(tag, "-"),
		})
	}
	if len(releases) == 0 {
		return nil, errors.New("GitHub returned no supported version tags")
	}
	sort.SliceStable(releases, func(left, right int) bool {
		return compareVersionTags(releases[left].Tag, releases[right].Tag) > 0
	})
	return releases, nil
}

type parsedVersion struct {
	major      int
	minor      int
	patch      int
	prerelease string
}

func compareVersionTags(left, right string) int {
	l, lok := parseVersionTag(left)
	r, rok := parseVersionTag(right)
	if !lok || !rok {
		return strings.Compare(left, right)
	}
	for _, pair := range [][2]int{{l.major, r.major}, {l.minor, r.minor}, {l.patch, r.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if l.prerelease == "" && r.prerelease != "" {
		return 1
	}
	if l.prerelease != "" && r.prerelease == "" {
		return -1
	}
	return comparePrerelease(l.prerelease, r.prerelease)
}

func parseVersionTag(value string) (parsedVersion, bool) {
	value = strings.TrimPrefix(value, "v")
	base, prerelease, _ := strings.Cut(value, "-")
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return parsedVersion{}, false
	}
	numbers := make([]int, 3)
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil {
			return parsedVersion{}, false
		}
		numbers[index] = number
	}
	return parsedVersion{
		major: numbers[0], minor: numbers[1], patch: numbers[2], prerelease: prerelease,
	}, true
}

func comparePrerelease(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for index := 0; index < max(len(leftParts), len(rightParts)); index++ {
		if index >= len(leftParts) {
			return -1
		}
		if index >= len(rightParts) {
			return 1
		}
		leftNumber, leftErr := strconv.Atoi(leftParts[index])
		rightNumber, rightErr := strconv.Atoi(rightParts[index])
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber < rightNumber {
				return -1
			}
			if leftNumber > rightNumber {
				return 1
			}
		case leftErr == nil:
			return -1
		case rightErr == nil:
			return 1
		default:
			if compared := strings.Compare(leftParts[index], rightParts[index]); compared != 0 {
				return compared
			}
		}
	}
	return 0
}

func catalogDiagnostic(err error) string {
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
	return "Version lookup failed: " + clean
}
