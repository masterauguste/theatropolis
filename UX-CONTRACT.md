# Theatropolis UX contract

This document records observable behavior shared by the authenticated web UI.
Security and domain rules in the Go implementation remain authoritative.

## Canonical UI Map

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Table Selection | Semantic table and labeled row controls | Server-rendered templates | Responsive row cards | Keyboard and narrow-viewport browser pass |
| Select/Listbox | Native select progressively enhanced by `dropdown.js` | Native select value and form validation | Explicit `data-native-select` escape hatch | Trigger geometry, keyboard, in-menu filter, incremental large-list rendering, scroll, close cleanup, and form submission tests |
| Date | Native date/time control | Server parser and fixed UTC+8 calendar rules | Date, time, and datetime-local | Locale and boundary tests |
| Form | Server-rendered form with CSRF and server validation | Go mutation handler | Inline, dialog, and destructive forms | Handler tests and duplicate-submit browser pass |
| Scrollbar | Global token-driven scrollbar | `app.css` root tokens | Bounded dialog and list scrollports | Desktop, narrow, forced-colors, and keyboard pass |
| Toast | Persistent inline status or stable destination state | Server response and async region | Copy affordance uses temporary button text | Mutation and async recovery tests |
| CRUD | Owning list/detail route plus explicit dialog actions | Go store and handler | Immediate user plane and transactional topology plane | Store, handler, and browser workflow tests |

## Navigation

- The primary destinations are Servers, Proxy Nodes, Users, Subscriptions, and
  Settings.
- End users have a separate read-only portal at `/portal`. It is not part of
  the operator navigation or operator session realm. The portal exposes only
  that user's configuration-subscription links, Node access, quota, reset
  time, and expiry state.
  Both the operator user detail and portal show the newest 30 UTC+8 calendar
  days of durable traffic history, grouped by day with a per-Node breakdown.
- `/login` is the single sign-in entry for administrators and end users. One
  role-tagged identity database owns the global username namespace, and one
  credential lookup determines the persisted role before a realm-specific
  session is issued. `/portal/login` redirects to this canonical entry. A
  username collision fails closed during migration or account claim; login
  never infers privilege by trying administrator and user verifiers in order.
- The active destination is visible through text, background, and the connected
  route-rail marker; it is also exposed with `aria-current="page"`.
- Breadcrumbs preserve ownership on detail and editor screens.
- A Proxy Node keeps its name, rename affordance, Users action, and Delete action
  in one page-header row. The Entrance Hop opens a dedicated listener/protocol
  dialog from the relay map; custom Rule Set management is not exposed.
  Membership forms stay in dialogs rather than the map canvas.
- Desktop uses a persistent left rail. Standard and focused-width pages remain
  centered in the available workspace on large displays, while topology pages
  retain the full canvas. Narrow layouts use a sticky horizontal header without
  hiding page content or document scrolling.
- A global user's Subscription destination owns only that user's bearer links
  and derived Nodes. The global Subscriptions destination owns the universal
  default route and ordered Rules used by every user export. Its Simplified
  Chinese navigation and page label is `配置订阅`; generic subscription fields
  such as link and expiry retain their context-specific wording.
- The Web UI supports English and Simplified Chinese (`zh-CN`). Simplified
  Chinese or English is selected from the browser's preferred languages on the
  first visit, with English as the fallback when neither language matches. That
  negotiated locale is stored as a one-year, host-scoped preference and takes
  precedence on later visits. The language control updates the same preference
  and returns to the current same-origin route; an untrusted referrer is never
  used as a redirect target. Navigation, document titles, validation, status
  text, authored controls, and client-generated feedback follow the active
  locale.

## Actions and forms

- Ordinary management POST forms use the shared submit handler in `app.js`:
  serialize before disabling controls, block duplicate writes, retain the form
  and focus its localized error on failure, and navigate only after success.
  Network errors are uncertain outcomes, never an automatic retry of a mutation.
- Background deployment or update completion must not reload a dirty document
  or an open editor. Show the shared refresh notice instead. Drafts remain only
  in document memory, never browser storage. Session expiry preserves drafts
  and offers sign-in in another tab. The next explicit submit refreshes the
  authenticated CSRF token before sending the retained form; it never replays
  a mutation automatically. Unsent input cannot be recovered by the Master.
- Migration export is an explicit download flow: await the archive, release the
  button on success or failure, and report completion without navigating away.
- The global Users list searches management names and login usernames and
  renders at most 50 results per page. Query and page belong in the URL; clamp
  an out-of-range page and distinguish an empty list from no search matches.
- `messages.json` is the shared English/Chinese message catalog. Templates call
  `t` explicitly; browser copy uses the same catalog. Do not reinstate substring
  translation of HTML, attributes, or user-entered names.
- Custom Rule Sets cannot be created or edited through the UI. Existing stored
  rules stay active and visible until converted or deleted; never silently
  discard legacy routing policy during an upgrade.
- Client export policy targets are `DIRECT`, `REJECT`, and `PROXY`; generated
  node names cannot collide with them. Protocol type names keep their required
  lowercase schema spelling. Domain-regex export limitations for Surge are visible.

- Primary buttons commit or create the page's main object. Secondary buttons
  save optional settings, cancel, close, refresh, or open supporting controls.
- Settings exposes Master migration as one compact header action. A role chooser
  opens separate source and destination dialogs: the source owns export and
  online-server cutover, while the destination owns restore. The two sides are
  never combined into one form or workflow surface.
- Add Server collects only identity and enrollment lifetime. Optional IPv4 and
  IPv6 configuration-subscription domains belong to the enrolled Server's
  settings dialog and save atomically. Invalid values reopen that dialog with
  both entered values preserved and the invalid field focused.
- Server names, Proxy Node names, and end-user management names are mutable,
  NFC-normalized display names. Their editors accept up to 60 Unicode letters,
  numbers, and combining marks plus ordinary spaces and `.`, `_`, or `-`.
  Immutable `agt_…`, `pn_…`, and `usr_…` IDs remain the routing, storage, and
  URL identities; renaming a Server updates labels without rewriting topology.
  An end user's separately claimed login username remains an ASCII login
  credential and is not derived from the management name.
- Visible button labels use title case.
- Danger actions remain visually and spatially distinct from routine saves.
- Revoking a Server is blocked while any desired or last-applied Proxy Node Hop
  uses that Agent, while its managed retirement profile is pending, or while a
  topology transaction is active. The administrator must first move or remove
  those Hops and let the old Agent receive its empty retirement configuration;
  revocation never silently deletes Proxy Node branches.
- Legacy topology references whose Server identity was already deleted are
  shown as deleted rather than offline. Their current selector value remains
  visible but cannot be reselected. Redirecting that Hop to an enrolled Server,
  deleting its branch, or deleting its Proxy Node removes the stale desired,
  applied, and managed references without waiting for an impossible remote
  cleanup acknowledgement. Enrolled but offline Servers retain the ordinary
  confirmed-cleanup requirement.
- Existing server-side validation is authoritative. Invalid submissions retain
  field values, expose an inline error summary, and identify invalid fields.
- Every product form disables browser-owned validation bubbles. The shared
  client validator renders localized inline errors, associates them with their
  fields, and focuses the first invalid control; server validation remains the
  final authority.
- Once a field is edited, syntax and range errors update in place on input,
  selection change, and focus exit; an untouched form does not begin in an
  error state. Proxy listener socket conflicts use the same field-owned error
  surface rather than appearing only after submission.
- A submitted form keeps button geometry stable and prevents duplicate submit.
- Credentials and tokens are masked by default and use the shared reveal
  control. Secrets never appear in URL state.
- Creating an end user records an operator-facing management name against an
  immutable hidden user ID. An operator may then generate a single-use,
  24-hour registration link at `/claim/{token}`. It becomes invalid immediately
  after successful registration or after its deadline. Before registration,
  an operator may explicitly reset the token; the old link becomes invalid and
  a fresh 24-hour link is generated. The token is exchanged into a short-lived,
  HttpOnly claim cookie and the browser is redirected to a clean URL before
  the user chooses a unique lowercase login name and password. The master
  stores only the invitation digest and a salted memory-hard password
  verifier. Public invitation claim can create only a `user` identity; the
  administrator role is not a form field and cannot be changed by that flow.

## Lists, tables, and search

- Fleet and accounting tables retain their semantic table markup and horizontally
  scroll within their own surface on intermediate widths.
- At phone widths, existing table rows become labeled cards without losing cell
  meaning.
- Search is local where the full option set is already present. Every search
  uses the canonical magnifier field, cobalt focus halo, and accessible clear
  action; clearing restores focus to the field.
- Proxy Node access on a global user is modeled as Node roles. Assigned roles
  are compact selectable chips; Add Node opens a searchable radio-list
  picker. One role is assigned at a time so its quota and subscription remain
  explicit, and only currently unassigned Nodes appear in the picker. The Add
  Node entry remains visible when every Node is assigned; the picker then
  shows its empty state without offering a mutation.
- The Proxy Node Users dialog owns its searchable access roster, add-user flow,
  subscription compensation, and per-membership maintenance dialogs. A finite
  active subscription remains compensable even when other global users are unassigned.
- Administrator Proxy Access is a global Settings toggle and defaults to off.
  Enabling it creates one protected Administrator Membership on every current
  Proxy Node and on Nodes created later; disabling it removes those Memberships,
  their live entrance credentials, and the administrator configuration
  subscription. The transition is one durable user-plane change and never waits
  for topology deployment. While enabled, each Administrator Membership is
  unlimited, never expires, remains visible in the roster, and cannot be
  renamed, edited, reset, compensated, revoked, or deleted. The administrator's
  configuration subscription follows the universal export policy.
- Each Server detail page summarizes entrance allocation from current Proxy
  Nodes assigned to that Agent. Finite Membership quotas and usage are summed
  per Membership; unlimited Membership traffic is excluded, while unlimited
  users are counted once per Agent even when they have several Nodes there.
  Add user remains visible when every existing user is assigned; its dialog
  shows an empty state without offering a duplicate grant.
- Empty states explain the next useful action. Async regions reserve their
  surface and provide loading, retry, expired-session, and empty states.
- Subscription Nodes are derived from each user's current Memberships. Nodes
  whose quota is exhausted remain visible with their stable credential while
  entrance authentication is disabled; they resume without re-import after the
  quota reset. Expired Nodes remain omitted. The
  universal Subscription Rules are explicitly ordered as draggable cards and
  use only Proxy, Direct, or Reject. Dropping a card atomically saves the complete
  order without reloading. During pointer drag, the dragged card remains a solid
  preview while sibling cards animate into their new positions; no insertion
  line is shown. Its handle also supports Arrow Up/Down as the non-drag
  alternative. `FINAL（未匹配规则）` selects the exported default action.
  Proxy is each export's generated group of active Nodes with Direct and Reject
  as its final manual choices. An empty group exposes Direct followed by Reject,
  so Direct is the default.
  Each Proxy Node owns a configuration-subscription address selector with
  IPv4-and-IPv6, IPv4-only, and IPv6-only choices. Newly created Nodes default
  to IPv4 only; existing Nodes retain their saved choice, and legacy Nodes with
  no saved choice retain the historical dual-stack behavior. For each selected
  family, an Agent's optional family-specific subscription domain replaces its
  discovered IP; otherwise the discovered IP remains the fallback. A configured
  domain may publish its family even when no IP has been discovered. The entrance
  TLS identity remains the exported SNI and is never replaced by this address
  metadata. An unavailable family with neither domain nor IP is omitted.
  Changing this selector updates subscription output without deploying topology.
  Geosite and GeoIP are selected directly as Rule matches through the shared
  searchable catalog selector; neither uses a provider-management or free-text
  surface.
  `No Resolve` is available only for destination IP/CIDR and GeoIP Rules. It
  emits the native flag for Clash and Surge and suppresses the matching
  sing-box pre-resolution action; domain-only Geosite Rules never expose it.
- Proxy Node topology Rules use the same searchable catalog selector for
  single-value Geosite and GeoIP matches; all other match types keep their
  established value editor.
- The persisted-state validator retains the older 96-character ASCII name
  ceiling only for upgrade compatibility; every new create or rename follows
  the 60-code-point editor contract. Display names never become protocol
  identities: generated authenticated-user labels contain the complete opaque
  Membership or Link ID without truncation. A trailing 12-character marker is
  retained only so older Agents can recognize the label during rolling upgrade.
- New AnyTLS and Hysteria2 listeners offer ACME or Agent-generated self-signed
  certificates and validate the certificate domain/IP while it is edited.
  Legacy file-backed certificate listeners remain loadable and compilable, but
  cannot be selected for a new listener or reused by another endpoint; editing
  one preserves its paths until the operator explicitly converts its mode.
- Link latency is advisory physical-path telemetry measured by the parent Agent
  every 30 seconds. AnyTLS and Shadowsocks 2022 use a TCP connect; Hysteria2
  uses an actual QUIC handshake, including the listener's configured
  obfuscation. Logical Links sharing the same parent, child address, and
  transport reuse one probe and one 30-day history. The relay map updates
  without navigation and preserves the last value during a transient UI fetch
  failure. A sample older than 90 seconds is stale and a failed handshake is
  unavailable. The UI never labels a reachable latency as good or bad by an
  arbitrary threshold. Link deletion hides its monitor but does not erase the
  shared physical-path history; retention removes it naturally after 30 days.
  History opens from the Link or Rule inspector in its own read-only monitor
  dialog and never appears inside relay editing. Destination selectors extend
  the canonical authored Select with the newest already-known physical-path
  latency; an Agent with no existing measured path is labelled Not measured.
  The draft relay editor's immediate probe remains separate from that history.

## Dialogs and transient layers

- The existing app-owned dialog is the canonical overlay. Background clicks do
  not close configuration dialogs; explicit Close/Cancel actions do.
- Dialog headers and footers stay fixed while long bodies scroll internally.
- Opening places focus inside the dialog; closing restores it to the invoker.
- Authored select/listbox popovers remain above dialog footers, clamp to the
  viewport, scroll internally, and use the same visual and keyboard contract
  in regular forms, listener editors, and routing editors. The closed trigger
  only displays the committed selection and owns exactly its visible hit area;
  opening the popover focuses a dedicated filter field above the option list.
  Page scrolling and mobile-keyboard viewport changes reposition an open
  popover instead of dismissing it. A pointer dismisses it only after a
  completed tap or click outside; touch-scroll gestures do not dismiss it.

## Mutation outcomes

- Proxy topology edits remain immediate and return to the relay map with no
  inspector opened unless the user explicitly selected one.
- When a saved topology cannot yet replace the running topology, the Proxy Node
  page persistently says that the relay map is showing saved, not active, state.
  Operational health is derived from both saved and last-applied snapshots:
  offline entrance roles use danger emphasis, offline relay roles use warning
  emphasis, and applied-only servers remain summarized as current topology until
  retirement completes. The relay map badges only offline Hops that actually
  exist in the saved tree; it never renders last-applied Hops as ghost nodes.
- A Proxy Node removed from saved state remains visible on the list as a
  read-only **Pending Removal** card while its last-applied configuration may
  still be running on an offline Agent. It disappears only after retirement is
  applied and never links back into the normal topology editor.
- A Link keeps showing active latency history only while its saved and applied
  physical probe identities match. A pending parent, destination, protocol,
  socket, TLS identity, or Hysteria2 obfuscation change shows Pending Apply with
  no historical samples until the new topology becomes active; draft probes in
  an open editor remain available.
- Moving a Hop changes only its assigned Agent and preserves the Hop identity,
  terminal, and downstream branches. Replacing a Link destination is an
  explicitly destructive dialog action: it preserves that Link's match and
  priority, deletes the old child subtree, rotates the relay credential, and
  creates a fresh terminal Hop on the selected Agent. Creating or replacing a
  Link never offers an Agent already traversed earlier on that branch, including
  the parent Agent; the topology store rejects the same choice from a forged
  request.
- User-plane changes apply immediately and never require a separate topology
  save.
- Membership quota reset and subscription expiration displays show their exact
  transition instants, not the preceding inclusive billing date. Billing
  boundaries remain calculated at UTC+8 midnight. When expiration and quota
  reset coincide, one atomic billing transition removes the expired Membership
  before processing quota resets for surviving grants. Removal also revokes the
  entrance credential and deletes that Membership's accounting history; access
  can return only through a new grant. The browser renders transition instants
  in the viewer's local timezone without a hard-coded timezone suffix.
- Every newly created user receives a subscription bearer token. Resetting the
  subscription link atomically rotates that token and all of the user's Proxy
  Node credentials; revoking the link changes only the token. A per-Node reset
  rotates only that Membership, while Reset all credentials preserves the
  subscription token. Every reset is server-confirmed, immediate, and shown in
  an app-owned confirmation dialog naming its scope and consequence.
- Per-Node credential rotation uses that same confirmation flow regardless of
  whether it was opened from the Proxy Node roster or the global user page.
- User-portal authentication is independent from configuration-subscription
  bearer tokens and Proxy Node credentials. Reset Login signs out all portal
  sessions, invalidates the password, and creates a new invitation; it does not
  rotate subscription URLs or Node credentials. User portal sessions use the
  same rolling seven-day inactivity window as operator sessions. After the
  shared credential entry has resolved the persisted role, administrator and
  user sessions retain separate host-only cookies and CSRF secrets so neither
  session realm is accepted by the other.
- Routine administrator and end-user interaction refreshes rolling session
  expiry in memory immediately. Activity snapshots are coalesced to at most one
  background write per minute; login, logout, credential reset, and revocation
  remain synchronous. This durability optimization does not impose a request
  rate limit or reduce the existing seven-day inactivity window.
- Async deployment/update state is shown in the existing stable inline region;
  errors remain recoverable and do not discard entered data.
- Session expiry returns the user to sign-in. Routine authenticated interaction
  keeps the rolling session active.

## Accessibility and resilience

Master restore is a staged pessimistic operation: validate the encrypted
archive, preserve the destination administrator, then restart into the already
validated state. It is available only on a fleet-empty destination and
invalidates browser sessions. Online Agent cutover is a separate explicit
action on the old Master; offline and incompatible Agents are reported as
skipped and never receive a queued command.

- Target WCAG 2.2 AA: native semantics, visible focus, labeled controls,
  meaningful status text, and keyboard alternatives for drag interactions.
- The app owns no hidden scrollbars. Content remains usable at 200% zoom and at
  a 320px viewport.
- Reduced-motion preference disables non-essential motion.
- Loading, error, empty, disabled, pending, and success states must not move the
  primary controls unexpectedly.
