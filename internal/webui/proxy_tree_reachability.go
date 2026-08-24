package webui

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

// proxyTreeConstraint describes the traffic that can reach one displayed Hop
// instance. Positive rules were selected on ancestor Hops. Negative rules are
// earlier first-match clauses that traffic on this path did not match.
type proxyTreeConstraint struct {
	positive []proxynode.Rule
	negative []proxynode.Rule
}

func (constraint proxyTreeConstraint) selectRule(rule proxynode.Rule, earlier []proxynode.Rule) proxyTreeConstraint {
	selected := proxyTreeConstraint{
		positive: append([]proxynode.Rule(nil), constraint.positive...),
		negative: append([]proxynode.Rule(nil), constraint.negative...),
	}
	selected.positive = append(selected.positive, rule)
	selected.negative = append(selected.negative, earlier...)
	return selected
}

func (constraint proxyTreeConstraint) selectFallback(earlier []proxynode.Rule) proxyTreeConstraint {
	selected := proxyTreeConstraint{
		positive: append([]proxynode.Rule(nil), constraint.positive...),
		negative: append([]proxynode.Rule(nil), constraint.negative...),
	}
	selected.negative = append(selected.negative, earlier...)
	return selected
}

// feasible is deliberately conservative. It removes a branch only when the
// supported rule fields prove that the path is empty. Regex and remote Rule
// Set relationships that cannot be proven locally remain visible.
func (constraint proxyTreeConstraint) feasible() bool {
	for left := range constraint.positive {
		for right := left + 1; right < len(constraint.positive); right++ {
			if !proxyRulesMayOverlap(constraint.positive[left], constraint.positive[right]) {
				return false
			}
		}
	}
	for _, excluded := range constraint.negative {
		if proxyRuleCoversConjunction(excluded, constraint.positive) {
			return false
		}
	}
	return true
}

// runtimeDependent reports whether local state is insufficient to prove the
// relationship. In particular, the master deliberately does not resolve a
// domain to test it against an IP rule: the child Agent's DNS answer is the one
// that matters and can vary over time and location.
func (constraint proxyTreeConstraint) runtimeDependent() bool {
	for left := range constraint.positive {
		for right := left + 1; right < len(constraint.positive); right++ {
			if proxyRuleRelationshipRuntimeDependent(constraint.positive[left], constraint.positive[right]) {
				return true
			}
		}
	}
	for _, excluded := range constraint.negative {
		if len(constraint.positive) == 0 && proxyDynamicRule(excluded.Match) {
			return true
		}
		for _, required := range constraint.positive {
			if proxyRuleRelationshipRuntimeDependent(excluded, required) {
				return true
			}
		}
	}
	return false
}

func proxyRuleRelationshipRuntimeDependent(left, right proxynode.Rule) bool {
	if proxyDynamicRule(left.Match) || proxyDynamicRule(right.Match) {
		return true
	}
	if (proxyDomainMatch(left.Match) && right.Match == proxynode.MatchIPCIDR) || (proxyDomainMatch(right.Match) && left.Match == proxynode.MatchIPCIDR) {
		return true
	}
	if left.Match == proxynode.MatchDomainRegex || right.Match == proxynode.MatchDomainRegex {
		// Exact-domain versus a valid regex is locally decidable; relationships
		// involving a suffix, keyword, or another regex are not.
		if left.Match == proxynode.MatchDomain && right.Match == proxynode.MatchDomainRegex {
			return !proxyRegexesValid(right.Values)
		}
		if right.Match == proxynode.MatchDomain && left.Match == proxynode.MatchDomainRegex {
			return !proxyRegexesValid(left.Values)
		}
		return true
	}
	return false
}

func proxyDynamicRule(match proxynode.MatchType) bool {
	return match == proxynode.MatchGeosite || match == proxynode.MatchGeoIP || match == proxynode.MatchRuleSet
}

func proxyRegexesValid(values []string) bool {
	for _, value := range values {
		if _, err := regexp.Compile(value); err != nil {
			return false
		}
	}
	return len(values) > 0
}

func proxyRuleCoversConjunction(cover proxynode.Rule, positive []proxynode.Rule) bool {
	if cover.Match == proxynode.MatchNone {
		return true
	}
	for _, required := range positive {
		if proxyRuleCovers(cover, required) {
			return true
		}
	}
	return false
}

func proxyRulesMayOverlap(left, right proxynode.Rule) bool {
	if left.Match == proxynode.MatchNone || right.Match == proxynode.MatchNone {
		return true
	}
	if proxyFiniteMatch(left.Match) && left.Match == right.Match {
		return proxyValuesIntersect(left.Values, right.Values, strings.ToLower)
	}
	if left.Match == proxynode.MatchIPCIDR && right.Match == proxynode.MatchIPCIDR {
		return proxyCIDRsOverlap(left.Values, right.Values)
	}
	if proxyDomainMatch(left.Match) && proxyDomainMatch(right.Match) {
		return proxyDomainRulesMayOverlap(left, right)
	}
	// Geosite, GeoIP, and custom Rule Set contents are not available here.
	// Different match dimensions can normally be true for the same flow.
	return true
}

func proxyRuleCovers(cover, covered proxynode.Rule) bool {
	if cover.Match == proxynode.MatchNone {
		return true
	}
	if covered.Match == proxynode.MatchNone {
		return false
	}
	if proxyFiniteMatch(cover.Match) && cover.Match == covered.Match {
		return proxyValuesCover(cover.Values, covered.Values, strings.ToLower)
	}
	if cover.Match == proxynode.MatchIPCIDR && covered.Match == proxynode.MatchIPCIDR {
		return proxyCIDRsCover(cover.Values, covered.Values)
	}
	if proxyDomainMatch(cover.Match) && proxyDomainMatch(covered.Match) {
		return proxyDomainRuleCovers(cover, covered)
	}
	if (cover.Match == proxynode.MatchGeosite || cover.Match == proxynode.MatchGeoIP || cover.Match == proxynode.MatchRuleSet) && cover.Match == covered.Match {
		return proxyValuesCover(cover.Values, covered.Values, strings.ToLower)
	}
	return false
}

func proxyFiniteMatch(match proxynode.MatchType) bool {
	return match == proxynode.MatchProtocol || match == proxynode.MatchNetwork || match == proxynode.MatchDomain
}

func proxyDomainMatch(match proxynode.MatchType) bool {
	switch match {
	case proxynode.MatchDomain, proxynode.MatchDomainSuffix, proxynode.MatchDomainKeyword, proxynode.MatchDomainRegex:
		return true
	default:
		return false
	}
}

func proxyDomainRulesMayOverlap(left, right proxynode.Rule) bool {
	if left.Match == proxynode.MatchDomain {
		return proxyExactDomainsMayMatch(left.Values, right)
	}
	if right.Match == proxynode.MatchDomain {
		return proxyExactDomainsMayMatch(right.Values, left)
	}
	if left.Match == proxynode.MatchDomainSuffix && right.Match == proxynode.MatchDomainSuffix {
		for _, leftValue := range left.Values {
			for _, rightValue := range right.Values {
				if proxyDomainHasSuffix(proxyDomainSuffix(leftValue), proxyDomainSuffix(rightValue)) || proxyDomainHasSuffix(proxyDomainSuffix(rightValue), proxyDomainSuffix(leftValue)) {
					return true
				}
			}
		}
		return false
	}
	// Keywords can coexist, and the intersection of arbitrary regexes or a
	// regex with a suffix cannot be proven empty without a regex automaton.
	return true
}

func proxyExactDomainsMayMatch(exactValues []string, other proxynode.Rule) bool {
	for _, value := range exactValues {
		domain := proxyDomain(value)
		for _, candidate := range other.Values {
			switch other.Match {
			case proxynode.MatchDomain:
				if domain == proxyDomain(candidate) {
					return true
				}
			case proxynode.MatchDomainSuffix:
				if proxyDomainHasSuffix(domain, proxyDomainSuffix(candidate)) {
					return true
				}
			case proxynode.MatchDomainKeyword:
				if strings.Contains(domain, strings.ToLower(candidate)) {
					return true
				}
			case proxynode.MatchDomainRegex:
				if expression, err := regexp.Compile(candidate); err != nil || expression.MatchString(value) || expression.MatchString(domain) {
					return true
				}
			}
		}
	}
	return false
}

func proxyDomainRuleCovers(cover, covered proxynode.Rule) bool {
	for _, value := range covered.Values {
		matched := false
		for _, candidate := range cover.Values {
			switch cover.Match {
			case proxynode.MatchDomain:
				matched = covered.Match == proxynode.MatchDomain && proxyDomain(candidate) == proxyDomain(value)
			case proxynode.MatchDomainSuffix:
				switch covered.Match {
				case proxynode.MatchDomain:
					matched = proxyDomainHasSuffix(proxyDomain(value), proxyDomainSuffix(candidate))
				case proxynode.MatchDomainSuffix:
					matched = proxyDomainHasSuffix(proxyDomainSuffix(value), proxyDomainSuffix(candidate))
				}
			case proxynode.MatchDomainKeyword:
				switch covered.Match {
				case proxynode.MatchDomain:
					matched = strings.Contains(proxyDomain(value), strings.ToLower(candidate))
				case proxynode.MatchDomainSuffix:
					matched = strings.Contains(proxyDomainSuffix(value), strings.ToLower(candidate))
				}
			case proxynode.MatchDomainRegex:
				if covered.Match == proxynode.MatchDomain {
					if expression, err := regexp.Compile(candidate); err == nil {
						matched = expression.MatchString(value) || expression.MatchString(proxyDomain(value))
					}
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(covered.Values) > 0
}

func proxyDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func proxyDomainSuffix(value string) string {
	return strings.Trim(proxyDomain(value), ".")
}

func proxyDomainHasSuffix(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}

func proxyValuesIntersect(left, right []string, normalize func(string) string) bool {
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[normalize(value)] = struct{}{}
	}
	for _, value := range right {
		if _, exists := values[normalize(value)]; exists {
			return true
		}
	}
	return false
}

func proxyValuesCover(cover, covered []string, normalize func(string) string) bool {
	values := make(map[string]struct{}, len(cover))
	for _, value := range cover {
		values[normalize(value)] = struct{}{}
	}
	for _, value := range covered {
		if _, exists := values[normalize(value)]; !exists {
			return false
		}
	}
	return len(covered) > 0
}

func proxyCIDRsOverlap(left, right []string) bool {
	leftPrefixes, leftOK := proxyPrefixes(left)
	rightPrefixes, rightOK := proxyPrefixes(right)
	if !leftOK || !rightOK {
		return true
	}
	for _, leftPrefix := range leftPrefixes {
		for _, rightPrefix := range rightPrefixes {
			if leftPrefix.Addr().BitLen() == rightPrefix.Addr().BitLen() && (leftPrefix.Contains(rightPrefix.Addr()) || rightPrefix.Contains(leftPrefix.Addr())) {
				return true
			}
		}
	}
	return false
}

func proxyCIDRsCover(cover, covered []string) bool {
	coverPrefixes, coverOK := proxyPrefixes(cover)
	coveredPrefixes, coveredOK := proxyPrefixes(covered)
	if !coverOK || !coveredOK {
		return false
	}
	for _, coveredPrefix := range coveredPrefixes {
		matched := false
		for _, coverPrefix := range coverPrefixes {
			if coverPrefix.Addr().BitLen() == coveredPrefix.Addr().BitLen() && coverPrefix.Bits() <= coveredPrefix.Bits() && coverPrefix.Contains(coveredPrefix.Addr()) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(coveredPrefixes) > 0
}

func proxyPrefixes(values []string) ([]netip.Prefix, bool) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(value)); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return nil, false
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	return prefixes, len(prefixes) > 0
}
