# Theatropolis design system

## Product character

Theatropolis is a control desk for operators who assemble and supervise proxy
routes across a server fleet. The interface should feel calm under pressure:
technical without looking industrial, light without becoming low-contrast, and
compact without feeling crowded.

The visual metaphor is a **signal path**. A thin connected route rail in the
navigation echoes the product's relay tree. This is the one signature device;
the surrounding surfaces stay flat, quiet, and precise.

## Visual principles

1. **Signal over decoration.** Lines, dots, labels, and color encode connection,
   hierarchy, status, or action. They are never ornamental flourishes.
2. **Light, not washed out.** White work surfaces sit on a cool cloud canvas.
   Text and controls meet WCAG 2.2 AA contrast.
3. **One strong action.** Cobalt is reserved for active navigation, focus, and
   the primary action. Status colors retain their semantic roles.
4. **Flat by default.** Borders and surface shifts define hierarchy. Shadows
   belong to floating layers and exceptional hover elevation only.
5. **Data stays legible.** Labels are compact, numbers use tabular figures, and
   identifiers use the shared monospace stack.

## Canonical tokens

`internal/webui/assets/app.css` is the runtime owner. Its `:root` block maps
these names to the legacy-compatible CSS variables consumed by all screens.

| Role | Value | Runtime mapping |
| --- | --- | --- |
| Canvas | `#f6f8fb` | `--paper` |
| Surface | `#ffffff` | `--surface` |
| Subtle surface | `#f0f3f8` | `--surface-sunken`, `--ink-100` |
| Primary ink | `#172033` | `--ink-950`, `--ink-900` |
| Secondary ink | `#5f6b7c` | `--ink-500` |
| Divider | `#dfe5ec` | `--ink-200` |
| Signal cobalt | `#4967e8` | `--accent-600` |
| Signal dark | `#304ec9` | `--accent-700`, `--accent-800` |
| Signal wash | `#eef1ff` | `--accent-100` |
| Success | `#187a55` / `#e9f7f1` | green tokens |
| Warning | `#9a6515` / `#fff6df` | amber tokens |
| Danger | `#c2414b` / `#fff0f1` | red tokens |

Proxy Node role identity uses a restrained five-color set (`blue`, `violet`,
`teal`, `amber`, and `coral`) with paired soft surfaces. These colors identify
Node assignments only; they never replace semantic success, warning, or danger
colors. The runtime owner is the `--role-*` family in `app.css`.

Typography uses the local system UI stack for headings and body text. Headings
use weight and spacing—not a display serif—to establish hierarchy. Identifiers,
addresses, versions, and configuration use the system monospace stack. No web
fonts or runtime font downloads are allowed.

English and Simplified Chinese share the same system-font stack and component
geometry. Chinese copy uses natural product terminology rather than compressed
literal translations; controls wrap when necessary and must never depend on an
English character count. Product and protocol names such as Theatropolis,
sing-box, AnyTLS, Hysteria2, Geosite, and GeoIP remain unchanged.
The global Subscriptions destination is `配置订阅` in Simplified Chinese, which
distinguishes exported client configurations from future service plans.
Account and access status uses `正常` for an enabled membership; `活动` is never
used as a literal translation of “Active.”

## Layout

Desktop uses a 14rem persistent route rail and a fluid work area. Standard
pages are centered within the space beside the rail and grow to a 120rem
maximum, so wide displays gain useful room without leaving the application
visually pinned to one edge. Focused form and settings pages use a centered
72rem maximum; topology views may use the entire remaining canvas. All three
variants share responsive outer padding. At narrow widths the rail becomes a
compact sticky top bar with horizontal navigation and document scrolling.

```text
┌ route rail ──────┬──────────────── work area ────────────────┐
│ mark + product   │ page title                         action │
│  ● Servers       │ ┌ summary ┐ ┌ summary ┐ ┌ summary ┐      │
│  │ Proxy Nodes   │ ┌─────────────────────────────────────┐  │
│  │ Users         │ │ primary table / route map / form    │  │
│  ● Settings      │ └─────────────────────────────────────┘  │
│                  │                                         │
│ Sign out         │                                         │
└──────────────────┴─────────────────────────────────────────┘
```

## Component rules

- Panels use a white surface, one-pixel divider, and 12px radius. They do not
  float unless they are interactive or modal.
- Buttons have 40px minimum height and title-case labels; primary is solid
  cobalt, secondary is white with a divider, and danger remains visually
  separated.
- Inputs use white surfaces, a clear border, and a cobalt focus halo. Every
  single-select uses the shared authored searchable dropdown: the field,
  chevron, menu surface, selected state, disabled state, and focus treatment
  stay identical across regular forms, dialogs, and routing editors.
- Tables use a subtle header surface and row dividers. Mobile rows retain the
  established stacked-card behavior.
- Dialogs use a dim cool backdrop, a restrained shadow, stable header/footer,
  and an internally scrolling body. The structural dialog shell never draws a
  focus ring; focus indication belongs to its actionable controls.
- The relay map uses the same cool surface system; connectors remain visible
  and rule cards carry the signal color without overpowering Hop nodes.
- A Proxy Node detail header keeps identity on the left and Users/Delete on the
  right; the name's compact pencil is the only rename affordance. Entrance
  listener/protocol editing belongs to a dedicated wide dialog opened directly
  from the Entrance Hop.
- Relay-map Hop cards use the assigned Agent as their only identity label.
  Routine Hop movement and destructive Link destination replacement are separate
  controls; replacement uses the standard danger dialog and states its subtree
  scope before submission.
- User access renders as compact Node-role chips: a colored identity mark,
  Node name, entrance context, and a text status. The searchable role picker is
  the canonical assignment surface; the color is supporting identity, not
  permission or health meaning.
- Proxy Node membership management uses the relay map's wide Users dialog. Its
  searchable roster opens focused access, grant, and compensation dialogs
  without turning the map canvas into a user-management dashboard.
- User subscription pages contain only a stable bearer-link surface and the
  read-only projection of that user's active Node roles. The global
  Subscriptions destination owns one compact ordered Rule ledger and the
  default Proxy/Direct/Reject outcome for every exported user profile.
- Search uses one canonical control: magnifier leading icon, white bordered
  surface, cobalt focus halo, and a trailing clear action that appears only
  when a query exists.
- All application-owned scroll regions inherit the global visible scrollbar
  treatment and retain forced-colors compatibility.

## Motion and accessibility

Motion is limited to 120–160ms color, border, and small position transitions.
No ambient animation is used. Reduced-motion preference collapses transitions
and animations. Keyboard focus is always visible, drag ordering keeps its
button alternative, and all text/status distinctions work without color alone.
