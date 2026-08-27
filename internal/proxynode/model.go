// Package proxynode owns the logical Proxy Node topology, users, generated
// credentials, rendering, and fleet deployment orchestration.
package proxynode

import "time"

const (
	SchemaID      = "theatropolis/proxy-node-state"
	SchemaVersion = 9
)

type Protocol string

const (
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolAnyTLS      Protocol = "anytls"
	ProtocolHysteria2   Protocol = "hysteria2"
)

type TLSMode string

const (
	TLSModeACME       TLSMode = "acme"
	TLSModeSelfSigned TLSMode = "self_signed"
	TLSModeFiles      TLSMode = "files"
)

type TargetType string

const (
	TargetDirect TargetType = "direct"
	TargetReject TargetType = "reject"
	TargetLink   TargetType = "link"
)

type MatchType string

const (
	MatchNone          MatchType = "none"
	MatchProtocol      MatchType = "protocol"
	MatchDomain        MatchType = "domain"
	MatchDomainSuffix  MatchType = "domain_suffix"
	MatchDomainKeyword MatchType = "domain_keyword"
	MatchDomainRegex   MatchType = "domain_regex"
	MatchIPCIDR        MatchType = "ip_cidr"
	MatchGeosite       MatchType = "geosite"
	MatchGeoIP         MatchType = "geoip"
	MatchRuleSet       MatchType = "rule_set"
	MatchNetwork       MatchType = "network"
)

type BuildInfo struct {
	Component  string    `json:"component"`
	Version    string    `json:"version"`
	Commit     string    `json:"commit"`
	RecordedAt time.Time `json:"recorded_at"`
}

type State struct {
	Revision            uint64               `json:"revision"`
	UserRevision        uint64               `json:"user_revision"`
	AppliedRevision     uint64               `json:"applied_revision"`
	Users               []User               `json:"users"`
	ProxyNodes          []ProxyNode          `json:"proxy_nodes"`
	AppliedProxyNodes   []ProxyNode          `json:"applied_proxy_nodes,omitempty"`
	ManagedAgents       []string             `json:"managed_agents,omitempty"`
	TrafficObservations []TrafficObservation `json:"traffic_observations,omitempty"`
	AccountingFailures  []AccountingFailure  `json:"accounting_failures,omitempty"`
}

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProxyNode struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Entrance    Entrance        `json:"entrance"`
	Hops        []Hop           `json:"hops"`
	Links       []Link          `json:"links"`
	Memberships []Membership    `json:"memberships"`
	RuleSets    []CustomRuleSet `json:"rule_sets,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type Entrance struct {
	HopID    string   `json:"hop_id"`
	Endpoint Endpoint `json:"endpoint"`
}

type Endpoint struct {
	Protocol   Protocol         `json:"protocol"`
	Listen     string           `json:"listen"`
	ListenPort int              `json:"listen_port"`
	Family     string           `json:"family,omitempty"`
	Method     string           `json:"method,omitempty"`
	ServerKey  string           `json:"server_key,omitempty"`
	Multiplex  *MultiplexConfig `json:"multiplex,omitempty"`
	TLS        TLSConfig        `json:"tls,omitempty"`
	UpMbps     int              `json:"up_mbps,omitempty"`
	DownMbps   int              `json:"down_mbps,omitempty"`
	ObfsType   string           `json:"obfs_type,omitempty"`
	ObfsSecret string           `json:"obfs_secret,omitempty"`
}

// MultiplexConfig records whether this logical Link's parent outbound uses
// multiplexing. A shared Shadowsocks listener enables inbound support when any
// attached Link requests it. Padding and Brutal remain persisted for backward
// compatibility but are not currently exposed by the guided editor.
type MultiplexConfig struct {
	Enabled bool             `json:"enabled"`
	Padding bool             `json:"padding,omitempty"`
	Brutal  *TCPBrutalConfig `json:"brutal,omitempty"`
}

type TCPBrutalConfig struct {
	Enabled  bool `json:"enabled"`
	UpMbps   int  `json:"up_mbps"`
	DownMbps int  `json:"down_mbps"`
}

type TLSConfig struct {
	Mode            TLSMode `json:"mode,omitempty"`
	ServerName      string  `json:"server_name,omitempty"`
	Email           string  `json:"email,omitempty"`
	CertificatePath string  `json:"certificate_path,omitempty"`
	KeyPath         string  `json:"key_path,omitempty"`
}

type Hop struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	AgentID     string    `json:"agent_id"`
	LegacyRules []Rule    `json:"rules,omitempty"`
	Final       Target    `json:"final"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Link struct {
	ID          string     `json:"id"`
	ParentHopID string     `json:"parent_hop_id"`
	ChildHopID  string     `json:"child_hop_id"`
	Order       int        `json:"order"`
	Rules       []Rule     `json:"rules,omitempty"`
	Fallback    bool       `json:"fallback,omitempty"`
	Endpoint    Endpoint   `json:"endpoint"`
	Credential  Credential `json:"credential"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Rule struct {
	ID           string    `json:"id"`
	Order        int       `json:"order"`
	Match        MatchType `json:"match"`
	Values       []string  `json:"values,omitempty"`
	LegacyTarget *Target   `json:"target,omitempty"`
}

type Target struct {
	Type   TargetType `json:"type"`
	LinkID string     `json:"link_id,omitempty"`
}

type Membership struct {
	ID                    string           `json:"id"`
	UserID                string           `json:"user_id"`
	Credential            Credential       `json:"credential"`
	PendingCredential     *Credential      `json:"pending_credential,omitempty"`
	MonthlyQuotaBytes     uint64           `json:"monthly_quota_bytes,omitempty"`
	UsedBytes             uint64           `json:"used_bytes,omitempty"`
	QuotaAnchorDay        int              `json:"quota_anchor_day"`
	QuotaPeriodStartedOn  time.Time        `json:"quota_period_started_on"`
	QuotaResetsAfter      time.Time        `json:"quota_resets_after"`
	SubscriptionStartedAt time.Time        `json:"subscription_started_at,omitempty"`
	SubscriptionEndsAfter time.Time        `json:"subscription_ends_after,omitempty"`
	SubscriptionValue     int              `json:"subscription_value,omitempty"`
	SubscriptionUnit      SubscriptionUnit `json:"subscription_unit,omitempty"`
	// LegacySubscriptionMonths is retained only so schema-v8 state can be decoded
	// and migrated. Schema-v9 state always leaves it zero.
	LegacySubscriptionMonths int              `json:"subscription_months,omitempty"`
	DisabledReason           MembershipStatus `json:"disabled_reason,omitempty"`
	CreatedAt                time.Time        `json:"created_at"`
}

type SubscriptionUnit string

const (
	SubscriptionMinutes SubscriptionUnit = "minutes"
	SubscriptionHours   SubscriptionUnit = "hours"
	SubscriptionDays    SubscriptionUnit = "days"
	SubscriptionMonths  SubscriptionUnit = "months"
)

type MembershipStatus string

const (
	MembershipEnabled      MembershipStatus = ""
	MembershipQuotaReached MembershipStatus = "quota_reached"
	MembershipExpired      MembershipStatus = "expired"
)

// MembershipPlan is the administrator-selected allowance for one user on one
// Proxy Node. A zero quota is unlimited; a zero subscription length never
// expires.
type MembershipPlan struct {
	MonthlyQuotaBytes uint64
	SubscriptionValue int
	SubscriptionUnit  SubscriptionUnit
}

// TrafficObservation is a rolling-upgrade baseline for a legacy Agent's
// cumulative counter. Reset-delta Agents do not create observations.
type TrafficObservation struct {
	AgentID       string    `json:"agent_id"`
	InboundPath   string    `json:"inbound_path"`
	Username      string    `json:"username"`
	Epoch         string    `json:"epoch"`
	UplinkBytes   uint64    `json:"uplink_bytes"`
	DownlinkBytes uint64    `json:"downlink_bytes"`
	ObservedAt    time.Time `json:"observed_at"`
}

// AccountingFailure is a bounded, non-sensitive master-side audit entry. It
// records that a sample could not be collected or persisted, never user names,
// traffic values, credentials, or raw Agent diagnostics.
type AccountingFailure struct {
	AgentID    string    `json:"agent_id"`
	Reason     string    `json:"reason"`
	OccurredAt time.Time `json:"occurred_at"`
}

type UserTraffic struct {
	InboundPath   string
	Username      string
	UplinkBytes   uint64
	DownlinkBytes uint64
}

type Credential struct {
	Secret string `json:"secret"`
}

type CustomRuleSet struct {
	Tag            string `json:"tag"`
	URL            string `json:"url"`
	Format         string `json:"format"`
	UpdateInterval string `json:"update_interval,omitempty"`
}

type CreateProxyNodeInput struct {
	Name      string
	RootName  string
	RootAgent string
	Entrance  Endpoint
	Final     Target
}

type AddLinkInput struct {
	ParentHopID string
	ChildName   string
	ChildAgent  string
	Endpoint    Endpoint
	Final       Target
}

type AddBranchInput struct {
	AddLinkInput
	Match  MatchType
	Values []string
}

type AddRuleInput struct {
	LinkID string
	Match  MatchType
	Values []string
}

type UpdateRuleInput struct {
	LinkID string
	Match  MatchType
	Values []string
}
