export interface SpaEnvelope<T = PageData> {
  view: string;
  status: number;
  locale: string;
  error?: string;
  errorField?: string;
  notice?: string;
  data: T;
  ok?: boolean;
  redirect?: string;
}

export interface SessionInfo {
  authenticated: boolean;
  role: "admin" | "user" | "";
  username?: string;
  csrfToken?: string;
  locale: string;
  publicURL: string;
  masterAddress: string;
  masterVersion: string;
  unifiedLogin: boolean;
  legacyLogin: boolean;
}

export interface PageData {
  ReverseOnly: boolean;
  Locale: string;
  Title: string;
  ActiveNav: string;
  AssetVersion: string;
  PublicURL: string;
  MasterAddress: string;
  CSRFToken: string;
  Error: string;
  ErrorField: string;
  Notice: string;
  Username: string;
  LegacyLogin: boolean;
  UnifiedLogin: boolean;
  AgentID: string;
  AgentName: string;
  TTLSeconds: number;
  Stats: FleetStats;
  Agents: AgentView[] | null;
  Agent: AgentDetailView | null;
  Created: CreatedServerView | null;
  AgentVersions: AgentVersionView[] | null;
  ReleaseCatalogWarning: string;
  LatestVersion: string;
  SingBoxVersions: AgentVersionView[] | null;
  SingBoxCatalogWarning: string;
  LatestSingBoxVersion: string;
  MasterVersion: string;
  MasterUpdateEnabled: boolean;
  MasterUpdate: AgentUpdateView | null;
  MasterUpdateRequestID: string;
  Pool: PoolView | null;
  PoolFormName: string;
  PoolFormRemark: string;
  PoolFormJSON: string;
  ProxyNodes: ProxyNodeListView[] | null;
  ProxyNode: ProxyNodeDetailView | null;
  EndUsers: EndUserListView[] | null;
  UserSearch: string;
  UserTotal: number;
  UserStart: number;
  UserEnd: number;
  UsersPreviousURL: string;
  UsersNextURL: string;
  EndUser: EndUserDetailView | null;
  UserSubscription: UserSubscriptionView | null;
  SubscriptionPolicy: SubscriptionPolicyView | null;
  EndUserLogin: EndUserLoginView | null;
  EndUserPortal: EndUserPortalView | null;
  AgentOptions: AgentOptionView[] | null;
  Endpoint: EndpointView;
  ListenerOptions: ListenerOptionView[] | null;
  ProxyDeployment: ProxyDeploymentView | null;
  AccountingFailures: AccountingFailureView[] | null;
  AccountingFailureTotal: number;
  AdministratorProxyAccessEnabled: boolean;
  MigrationNotice: string;
}

export interface FleetStats {
  Total: number;
  Online: number;
  Pending: number;
  Attention: number;
}

export interface AgentView {
  ID: string;
  Name: string;
  EnrollmentLabel: string;
  EnrollmentClass: string;
  ConnectionLabel: string;
  ConnectionClass: string;
  Detail: string;
  URL: string;
  IPv4: string;
  IPv6: string;
  AgentVersion: string;
  SingBoxVersion: string;
}

export interface AgentDetailView {
  ReverseOnly: boolean;
  ID: string;
  Name: string;
  URL: string;
  Online: boolean;
  DeploymentStatusURL: string;
  EnrollmentLabel: string;
  EnrollmentClass: string;
  ConnectionLabel: string;
  ConnectionClass: string;
  ConnectionDetail: string;
  Configuration: string;
  ConfigurationEnabled: boolean;
  ConfigurationEditable: boolean;
  ConfigurationHint: string;
  Deployment: DeploymentView | null;
  AgentVersion: string;
  OperatingSystem: string;
  Architecture: string;
  SingBoxVersion: string;
  ACMEHTTP01Relay: boolean;
  SingBoxUpdateEnabled: boolean;
  SingBoxUpdateHint: string;
  SingBoxUpdateTarget: string;
  SingBoxUpdate: AgentUpdateView | null;
  UpdateEnabled: boolean;
  UpdateHint: string;
  UpdateTarget: string;
  Update: AgentUpdateView | null;
  RevokeLabel: string;
  CanReplace: boolean;
  SubscriptionDomainV4: string;
  SubscriptionDomainV6: string;
  IPv4: string;
  IPv6: string;
  EntranceAllocated: string;
  EntranceUsed: string;
  EntranceUnlimited: number;
  ProxyNodeReferences: AgentProxyNodeReferenceView[] | null;
  RemovalBlocked: boolean;
  RetirementPending: boolean;
  CanForceRemove: boolean;
}

export interface AgentProxyNodeReferenceView {
  ID: string;
  Name: string;
  URL: string;
  Desired: boolean;
  DesiredEntrance: boolean;
  DesiredRelayHops: number;
  DesiredRelayHopLabel: string;
  Applied: boolean;
  AppliedEntrance: boolean;
  AppliedRelayHops: number;
  AppliedRelayHopLabel: string;
}

export interface AgentUpdateView {
  TargetVersion: string;
  RunningVersion: string;
  StatusLabel: string;
  StatusClass: string;
  Diagnostic: string;
  UpdatedAt: string;
}

export interface AgentVersionView {
  Tag: string;
  Branch: string;
}

export interface DeploymentView {
  ID: string;
  RevisionID: string;
  StatusLabel: string;
  StatusClass: string;
  Diagnostic: string;
  Digest: string;
  UpdatedAt: string;
  Pending: boolean;
}

export interface CreatedServerView {
  AgentID: string;
  DisplayName: string;
  InstallCommand: string;
  ExpiresAt: string;
  ExpiresAtISO: string;
}

export interface AccountingFailureView {
  AgentID: string;
  AgentName: string;
  Reason: string;
  OccurredAt: string;
}

export interface PoolUserView {
  Label: string;
  Ref: string;
}

export interface PoolInboundView {
  DialogID: string;
  AgentID: string;
  AgentName: string;
  Tag: string;
  Type: string;
  Port: number;
  IPv4: string;
  IPv6: string;
  Users: PoolUserView[] | null;
  AddressURL: string;
  OverrideV4: string;
  OverrideV6: string;
}

export interface PoolManualView {
  Name: string;
  Remark: string;
  Type: string;
  Port: number;
  Outbound: string;
}

export interface PoolView {
  Inbounds: PoolInboundView[] | null;
  Manual: PoolManualView[] | null;
  Diagnostics: string[] | null;
}

export interface ProxyNodeListView {
  ID: string;
  Name: string;
  URL: string;
  Entrance: string;
  EntranceAgent: string;
  HopCount: number;
  MemberCount: number;
  UpdatedAt: string;
  PendingApply: boolean;
  PendingRemoval: boolean;
  EntranceDeleted: boolean;
  RelayDeleted: boolean;
  EntranceOffline: boolean;
  RelayOffline: boolean;
}

export interface ProxyNodeOfflineAgentView {
  Name: string;
  Applied: boolean;
}

export interface ProxyNodeOperationalStatusView {
  TopologyPending: boolean;
  EntranceDeleted: ProxyNodeOfflineAgentView[] | null;
  RelayDeleted: ProxyNodeOfflineAgentView[] | null;
  EntranceOffline: ProxyNodeOfflineAgentView[] | null;
  RelayOffline: ProxyNodeOfflineAgentView[] | null;
}

export interface MembershipPlanView {
  QuotaMode: string;
  QuotaGiB: string;
  ExpirationMode: string;
  SubscriptionValue: string;
  SubscriptionUnit: string;
  CanExtend: boolean;
  QuotaLabel: string;
  UsageLabel: string;
  ResetLabel: string;
  ResetAt: string;
  ExpirationLabel: string;
  ExpirationAt: string;
  StatusLabel: string;
  StatusClass: string;
}

export interface NodeUserAccessView {
  UserID: string;
  MembershipID: string;
  Name: string;
  Initial: string;
  URL: string;
  Plan: MembershipPlanView;
  SubscriptionStartedAt: string;
  SubscriptionEndsAfter: string;
  CompensationSelected: boolean;
  System: boolean;
}

export interface NodeUserOptionView {
  UserID: string;
  Label: string;
}

export interface AgentOptionView {
  ReverseOnly: boolean;
  ID: string;
  Name: string;
  Selected: boolean;
  Online: boolean;
  Deleted: boolean;
  LatencyDetail: string;
  LatencyStatus: string;
  LatencyLinkIDs: string;
}

export interface EndpointView {
  AllowReverse: boolean;
  ParentAgentID: string;
  AgentID: string;
  ListenerID: string;
  Protocol: string;
  ProtocolLabel: string;
  Listen: string;
  ListenPort: number;
  Family: string;
  Method: string;
  MuxEnabled: boolean;
  MuxPadding: boolean;
  MuxBrutal: boolean;
  MuxBrutalUpMbps: number;
  MuxBrutalDownMbps: number;
  TLSMode: string;
  ServerName: string;
  Email: string;
  CertificatePath: string;
  KeyPath: string;
  UpMbps: number;
  DownMbps: number;
  ObfsType: string;
}

export interface ListenerOptionView {
  ID: string;
  AgentID: string;
  Label: string;
  Protocol: string;
  ProtocolLabel: string;
  Listen: string;
  ListenPort: number;
  Method: string;
  MuxPadding: boolean;
  MuxBrutal: boolean;
  MuxBrutalUp: number;
  MuxBrutalDown: number;
  TLSMode: string;
  ServerName: string;
  Email: string;
  CertificatePath: string;
  KeyPath: string;
  UpMbps: number;
  DownMbps: number;
  ObfsType: string;
  ReferenceCount: number;
}

export interface ProxyRuleView {
  ID: string;
  Position: number;
  Match: string;
  MatchLabel: string;
  Values: string;
  FormValues: string;
  CanMoveUp: boolean;
  CanMoveDown: boolean;
}

export interface LinkLatencyView {
  status: string;
  label: string;
  detail?: string;
  probe_type?: string;
  observed_at?: string;
}

export interface LinkLatencyPointView {
  at: string;
  samples: number;
  responses: number;
  average_ms: number;
  minimum_ms: number;
  maximum_ms: number;
  loss_percent: number;
}

export interface ProxyBlockRuleView {
  Rule: ProxyRuleView;
  AgentID: string;
  Name: string;
  ParentID: string;
}

export interface ProxyTreeRouteView {
  InspectorID: string;
  ProxyID: string;
  HopID: string;
  CSRFToken: string;
  Label: string;
  Match: string;
  Values: string;
  TargetLabel: string;
  TargetDetail: string;
  TargetKind: string;
  TargetURL: string;
  Uncertain: boolean;
}

export interface ProxyTreeLinkView {
  ID: string;
  ParentHopID: string;
  EditURL: string;
  Protocol: string;
  ListenPort: number;
  Listener: string;
  Family: string;
  Order: number;
  Endpoint: EndpointView;
  Rules: ProxyRuleView[] | null;
  NewRule: ProxyRuleView;
  Used: boolean;
  Fallback: boolean;
  CanMoveUp: boolean;
  CanMoveDown: boolean;
  Child: ProxyTreeHopView | null;
  Latency: LinkLatencyView;
  HistoryURL: string;
  ProbeURL: string;
  DestinationAgentOptions: AgentOptionView[] | null;
}

export interface ProxyTreeBranchView {
  LinkID: string;
  RuleID: string;
  RulePosition: number;
  Protocol: string;
  RuleLabel: string;
  RuleValues: string;
  Used: boolean;
  Fallback: boolean;
  Block: boolean;
  InspectorID: string;
  AgentID: string;
  Name: string;
  Uncertain: boolean;
  Child: ProxyTreeHopView | null;
  Latency: LinkLatencyView;
}

export interface ProxyTreeHopView {
  ProxyID: string;
  ID: string;
  Name: string;
  AgentID: string;
  URL: string;
  IsEntrance: boolean;
  Deleted: boolean;
  Offline: boolean;
  IngressProtocol: string;
  IngressLabel: string;
  Routes: ProxyTreeRouteView[] | null;
  Fallback: ProxyTreeRouteView;
  ShowFallback: boolean;
  Children: ProxyTreeLinkView[] | null;
  BlockRules: ProxyBlockRuleView[] | null;
  Branches: ProxyTreeBranchView[] | null;
  AllRuleIDs: string;
  TerminalCount: number;
  RuntimeBranches: number;
  BranchCount: number;
  Final: string;
  AgentOptions: AgentOptionView[] | null;
  DestinationAgentOptions: AgentOptionView[] | null;
  NewRule: ProxyRuleView;
  NewLinkEndpoint: EndpointView;
  CSRFToken: string;
}

export interface ProxyNodeDetailView {
  ID: string;
  Name: string;
  URL: string;
  UsersURL: string;
  EntranceFallback: string;
  Entrance: EndpointView;
  Tree: ProxyTreeHopView | null;
  HopCount: number;
  LinkCount: number;
  MemberCount: number;
  EndUserCount: number;
  FiniteMemberCount: number;
  CompensationStart: string;
  CompensationEnd: string;
  CompensationSelected: number;
  TerminalCount: number;
  UnusedLinkCount: number;
  UserAccess: NodeUserAccessView[] | null;
  AvailableUsers: NodeUserOptionView[] | null;
  DefaultPlan: MembershipPlanView;
  SubscriptionAddressMode: string;
  OperationalStatus: ProxyNodeOperationalStatusView;
}

export interface ProxyDeploymentAgentView {
  agent_id: string;
  agent_name: string;
  status: string;
}

export interface ProxyDeploymentView {
  id: string;
  status: string;
  label: string;
  class: string;
  error?: string;
  active: boolean;
  agents?: ProxyDeploymentAgentView[];
}

export interface EndUserListView {
  ID: string;
  Name: string;
  URL: string;
  Memberships: number;
  LoginUsername: string;
  LoginStatus: string;
  LoginClass: string;
}

export interface DailyUsageNodeView {
  ProxyNodeID: string;
  Name: string;
  UsageLabel: string;
}

export interface DailyUsageDayView {
  Date: string;
  DateLabel: string;
  Total: number;
  TotalLabel: string;
  Nodes: DailyUsageNodeView[] | null;
}

export interface EndUserInvitationView {
  URL: string;
  ExpiresAt: string;
}

export interface EndUserLoginAccessView {
  Claimed: boolean;
  LoginUsername: string;
  StatusLabel: string;
  StatusClass: string;
  InvitationReady: boolean;
  InviteExpiresAt: string;
  Invitation: EndUserInvitationView | null;
}

export interface CredentialURIView {
  Family: string;
  URI: string;
}

export interface UserProxyAccessView {
  UserName: string;
  ProxyID: string;
  ProxyName: string;
  ProxyURL: string;
  DialogID: string;
  Initial: string;
  Tone: string;
  EntranceLabel: string;
  EntranceAgent: string;
  AuthUser: string;
  URIs: CredentialURIView[] | null;
  Plan: MembershipPlanView;
}

export interface UserProxyOptionView {
  ProxyID: string;
  ProxyName: string;
  EntranceLabel: string;
  EntranceAgent: string;
  Initial: string;
  Tone: string;
}

export interface EndUserDetailView {
  ID: string;
  Name: string;
  ProxyNodeCount: number;
  AssignedAccess: UserProxyAccessView[] | null;
  AvailableAccess: UserProxyOptionView[] | null;
  DefaultPlan: MembershipPlanView;
  Login: EndUserLoginAccessView;
  DailyUsage: DailyUsageDayView[] | null;
}

export interface SubscriptionNodeView {
  Name: string;
  Initial: string;
  Protocol: string;
  AgentID: string;
  AgentName: string;
  Status: string;
  StatusCSS: string;
  Addresses: string[] | null;
}

export interface UserSubscriptionView {
  UserID: string;
  UserName: string;
  Enabled: boolean;
  ClashURL: string;
  SurgeURL: string;
  SingBoxURL: string;
  Nodes: SubscriptionNodeView[] | null;
  System: boolean;
}

export interface SubscriptionTargetOption {
  Value: string;
  Label: string;
  Kind: string;
  Selected: boolean;
  Builtin: boolean;
}

export interface SubscriptionTargetPicker {
  Action: string;
  Options: SubscriptionTargetOption[] | null;
}

export interface SubscriptionGroupView {
  ID: string;
  Name: string;
  Type: string;
  Members: string;
  AllNodes: boolean;
  Interval: number;
  Tolerance: number;
  References: number;
  Choices: SubscriptionTargetOption[] | null;
  Replacement: SubscriptionTargetPicker;
}

export interface SubscriptionRuleView {
  Targets: SubscriptionTargetPicker;
  ID: string;
  Position: number;
  Match: string;
  MatchLabel: string;
  Values: string;
  Summary: string;
  Action: string;
  ActionLabel: string;
  NoResolve: boolean;
  CanMoveUp: boolean;
  CanMoveDown: boolean;
}

export interface SubscriptionPolicyView {
  DefaultTargets: SubscriptionTargetPicker;
  NewRuleTargets: SubscriptionTargetPicker;
  Groups: SubscriptionGroupView[] | null;
  NewGroup: SubscriptionGroupView;
  DefaultAction: string;
  Rules: SubscriptionRuleView[] | null;
}

export interface EndUserLoginView {
  Username: string;
  Unavailable: boolean;
  ReturnTo: string;
}

export interface EndUserPortalNodeView {
  Name: string;
  Initial: string;
  Tone: string;
  Protocol: string;
  EntranceAgent: string;
  PendingApply: boolean;
  UsageLabel: string;
  QuotaLabel: string;
  ResetLabel: string;
  ResetAt: string;
  ExpirationLabel: string;
  ExpirationAt: string;
  StatusLabel: string;
  StatusClass: string;
}

export interface EndUserPortalView {
  LoginUsername: string;
  CSRFToken: string;
  Subscription: UserSubscriptionView | null;
  Nodes: EndUserPortalNodeView[] | null;
  DailyUsage: DailyUsageDayView[] | null;
}

export interface VersionCatalogResponse {
  latest_version?: string;
  agent_catalog_warning?: string;
  sing_box_versions?: AgentVersionView[];
  latest_sing_box_version?: string;
  sing_box_catalog_warning?: string;
  error?: string;
}
