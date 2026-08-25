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
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
)

const maxReleaseResponseSize = 2 << 20

var gitTagReferencePattern = regexp.MustCompile(`refs/tags/([^\x00\s^]+)`)

type AgentRelease struct {
	Tag         string
	Prerelease  bool
	PublishedAt time.Time
}

type ReleaseCatalog interface {
	Versions(context.Context) ([]AgentRelease, error)
}

// GitHubReleaseCatalog discovers Theatropolis releases through GitHub's release
// metadata so a tag is not offered until every supported binary and its checksum
// manifest exist. The sing-box catalog applies the same rule to the dedicated,
// signed V2Ray-API build repository.
type GitHubReleaseCatalog struct {
	client         *http.Client
	refsURL        string
	releasesURL    string
	requiredAssets []string
	validVersion   func(string) bool
}

func NewGitHubReleaseCatalog(client *http.Client) *GitHubReleaseCatalog {
	if client == nil {
		client = &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(request *http.Request, _ []*http.Request) error {
				host := request.URL.Hostname()
				if request.URL.Scheme != "https" ||
					(host != "github.com" && host != "api.github.com") {
					return errors.New("version catalog redirected to an untrusted host")
				}
				return nil
			},
		}
	}
	return &GitHubReleaseCatalog{
		client:      client,
		releasesURL: "https://api.github.com/repos/masterauguste/theatropolis/releases?per_page=100",
		requiredAssets: []string{
			"checksums.txt",
			"checksums.txt.sig",
			"theatropolis_linux_amd64.tar.gz",
			"theatropolis_linux_arm64.tar.gz",
		},
		validVersion: agentupdate.ValidVersion,
	}
}

func NewSingBoxReleaseCatalog(client *http.Client) *GitHubReleaseCatalog {
	catalog := NewGitHubReleaseCatalog(client)
	catalog.releasesURL = "https://api.github.com/repos/" + singboxupdate.ReleaseRepository + "/releases?per_page=100"
	catalog.requiredAssets = []string{
		"checksums.txt",
		"checksums.txt.sig",
		"sing-box-{version}-linux-amd64.tar.gz",
		"sing-box-{version}-linux-arm64.tar.gz",
	}
	catalog.validVersion = singboxupdate.ValidVersion
	return catalog
}

func (c *GitHubReleaseCatalog) Versions(ctx context.Context) ([]AgentRelease, error) {
	return c.fetch(ctx)
}

func (c *GitHubReleaseCatalog) fetch(ctx context.Context) ([]AgentRelease, error) {
	if c.releasesURL != "" {
		return c.fetchPublishedReleases(ctx)
	}
	return c.fetchTags(ctx)
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Draft       bool      `json:"draft"`
	Assets      []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

func (c *GitHubReleaseCatalog) fetchPublishedReleases(
	ctx context.Context,
) ([]AgentRelease, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.releasesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare release discovery: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request GitHub releases: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub release discovery returned status %d", response.StatusCode)
	}
	if response.ContentLength > maxReleaseResponseSize {
		return nil, errors.New("GitHub release response exceeds the size limit")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxReleaseResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub releases: %w", err)
	}
	if len(encoded) > maxReleaseResponseSize {
		return nil, errors.New("GitHub release response exceeds the size limit")
	}
	var published []githubRelease
	if err := json.Unmarshal(encoded, &published); err != nil {
		return nil, fmt.Errorf("decode GitHub releases: %w", err)
	}
	releases := make([]AgentRelease, 0, len(published))
	for _, release := range published {
		if release.Draft || !c.validVersion(release.TagName) ||
			!hasReleaseAssets(release, c.requiredAssets) {
			continue
		}
		releases = append(releases, AgentRelease{
			Tag:         release.TagName,
			Prerelease:  release.Prerelease,
			PublishedAt: release.PublishedAt,
		})
	}
	if len(releases) == 0 {
		return nil, errors.New("GitHub returned no supported releases with downloadable binaries")
	}
	sort.SliceStable(releases, func(left, right int) bool {
		return compareVersionTags(releases[left].Tag, releases[right].Tag) > 0
	})
	return releases, nil
}

func hasReleaseAssets(release githubRelease, required []string) bool {
	assets := make(map[string]struct{}, len(release.Assets))
	for _, asset := range release.Assets {
		assets[asset.Name] = struct{}{}
	}
	for _, name := range required {
		name = strings.ReplaceAll(
			name,
			"{version}",
			strings.TrimPrefix(release.TagName, "v"),
		)
		if _, exists := assets[name]; !exists {
			return false
		}
	}
	return true
}

func (c *GitHubReleaseCatalog) fetchTags(ctx context.Context) ([]AgentRelease, error) {
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
