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
- The Web UI supports English and Simplified Chinese (`zh-CN`). Browser language
  selects the first visit, while the explicit language control stores a
  one-year, host-scoped preference and takes precedence afterward. The switch
  returns to the current same-origin route; an untrusted referrer is never used
  as a redirect target. Navigation, document titles, validation, status text,
  authored controls, and client-generated feedback follow the active locale.

## Actions and forms

- Primary buttons commit or create the page's main object. Secondary buttons
  save optional settings, cancel, close, refresh, or open supporting controls.
- Visible button labels use title case.
- Danger actions remain visually and spatially distinct from routine saves.
- Existing server-side validation is authoritative. Invalid submissions retain
  field values, expose an inline error summary, and identify invalid fields.
- Every product form disables browser-owned validation bubbles. The shared
  client validator renders localized inline errors, associates them with their
  fields, and focuses the first invalid control; server validation remains the
  final authority.
- A submitted form keeps button geometry stable and prevents duplicate submit.
- Credentials and tokens are masked by default and use the shared reveal
  control. Secrets never appear in URL state.

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
  subscription remains compensable even when other global users are unassigned.
  Add user remains visible when every existing user is assigned; its dialog
  shows an empty state without offering a duplicate grant.
- Empty states explain the next useful action. Async regions reserve their
  surface and provide loading, retry, expired-session, and empty states.
- Subscription Nodes are derived from each user's current Memberships. Nodes
  whose quota is exhausted remain visible with their stable credential while
  entrance authentication is disabled; they resume without re-import after the
  quota reset. Expired Nodes remain omitted. The
  universal Subscription Rules are explicitly ordered and use only Proxy,
  Direct, or Reject; Proxy is each export's generated group of active Nodes with
  Direct and Reject as its final manual choices. An empty group exposes Direct
  followed by Reject, so Direct is the default.
  Each Proxy Node owns a configuration-subscription address selector with
  IPv4-and-IPv6, IPv4-only, and IPv6-only choices. Existing and newly created
  Nodes default to both families; an unavailable selected family is omitted.
  Changing this selector updates subscription output without deploying topology.
  Geosite is selected directly as a Rule match through the shared searchable
  catalog selector; no provider-management or free-text Geosite surface exists.
- Proxy Node topology Rules use the same searchable catalog selector for
  single-value Geosite and GeoIP matches; all other match types keep their
  established value editor.

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

## Mutation outcomes

- Proxy topology edits remain immediate and return to the relay map with no
  inspector opened unless the user explicitly selected one.
- Moving a Hop changes only its assigned Agent and preserves the Hop identity,
  terminal, and downstream branches. Replacing a Link destination is an
  explicitly destructive dialog action: it preserves that Link's match and
  priority, deletes the old child subtree, rotates the relay credential, and
  creates a fresh terminal Hop on the selected Agent.
- User-plane changes apply immediately and never require a separate topology
  save.
- Every newly created user receives a subscription bearer token. Resetting the
  subscription link atomically rotates that token and all of the user's Proxy
  Node credentials; revoking the link changes only the token. A per-Node reset
  rotates only that Membership, while Reset all credentials preserves the
  subscription token. Every reset is server-confirmed, immediate, and shown in
  an app-owned confirmation dialog naming its scope and consequence.
- Per-Node credential rotation uses that same confirmation flow regardless of
  whether it was opened from the Proxy Node roster or the global user page.
- Async deployment/update state is shown in the existing stable inline region;
  errors remain recoverable and do not discard entered data.
- Session expiry returns the user to sign-in. Routine authenticated interaction
  keeps the rolling session active.

## Accessibility and resilience

- Target WCAG 2.2 AA: native semantics, visible focus, labeled controls,
  meaningful status text, and keyboard alternatives for drag interactions.
- The app owns no hidden scrollbars. Content remains usable at 200% zoom and at
  a 320px viewport.
- Reduced-motion preference disables non-essential motion.
- Loading, error, empty, disabled, pending, and success states must not move the
  primary controls unexpectedly.
