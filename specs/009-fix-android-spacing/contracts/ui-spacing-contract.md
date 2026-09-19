# UI Layout & Spacing Contract

**Feature Directory**: `specs/009-fix-android-spacing`  
**Contract Version**: 1.0.0  
**Status**: Ratified  

---

## 1. Scope & Target Selectors

This contract governs the responsive design behavior, flexbox axes, spacing intervals, and container padding across mobile ($\le 680\text{px}$) and wide desktop ($> 680\text{px}$) viewports in both `apps/android` and `apps/desktop`.

---

## 2. Breakpoint Definitions

| Token | Breakpoint | Target Surface |
| :--- | :--- | :--- |
| `bp-mobile` | `max-width: 680px` | Android mobile devices in portrait/landscape, small desktop windows |
| `bp-compact` | `max-width: 380px` | Ultra-compact Android displays (e.g. 360px wide devices) |
| `bp-desktop` | `min-width: 681px` | Tablets in landscape, desktop application windows |

---

## 3. Selector Specifications & Layout Guarantees

### 3.1 Container Views (`.home-view`, `.settings-view`, `.logs-view`, `.scanner-view`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `max-width` | `min(100%, 1080px)` | `100%` | Cards never overflow horizontally |
| `padding` | `24px 32px 44px` | `14px 14px 24px` | No wasted margins on mobile screens |
| `display` | `grid` | `grid` | Grid layout for consistent stacking |
| `gap` | `16px` | `12px` | 25% tighter gap between cards |

### 3.2 Card Panels (`.settings-section`, `.tactical-panel`, `.proxy-panel`, `.profiles-panel`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `margin-top` | `0` (inside grid) | `0` | Eliminates stacked redundant margins |
| `border-radius` | `14px` | `14px` | Retains tactical rounded card aesthetic |
| `overflow` | `hidden` | `hidden` | Prevents child elements overflowing |

### 3.3 Card Headings (`.section-heading`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `min-height` | `68px` | `48px` | 20px saved on each card header |
| `padding` | `16px 22px` | `12px 16px` | Balanced header spacing |
| `display` | `flex` | `flex` | Icon and title alignment |
| `align-items` | `center` | `center` | Vertically centered header items |

### 3.4 Setting Rows (`.setting-row`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `display` | `flex` | `flex` | Standard flex layout |
| `flex-direction` | `row` | `column` | Clean vertical flow on mobile |
| `align-items` | `center` | `stretch` | Controls span full card width on mobile |
| `justify-content`| `space-between` | `flex-start` | Controls sit directly under descriptions |
| `gap` | `20px` | `10px` | Instant proximity between label & input |
| `min-height` | `68px` | `auto` | Natural content-driven height |
| `padding` | `16px 22px` | `14px 16px` | Compact row padding |

### 3.5 Setting Title Block (`.setting-row > div:first-child`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `flex` | `1 1 240px` | `0 0 auto` | **ZERO vertical height expansion** |
| `width` | `auto` | `100%` | Wraps description cleanly across width |
| `min-width` | `0` | `0` | Text overflow safe |

### 3.6 Multi-Field Input Blocks (`.port-field-block`, `.param-field-block`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `flex` | `1 1 200px` | `1 1 auto` | **ZERO arbitrary 200px vertical gaps** |
| `width` | `auto` | `100%` | Full width on stacked mobile layout |
| `min-width` | `0` | `0` | No horizontal clipping |

### 3.7 Form Controls (`.tactical-select`, `.segmented`)

| Selector | Property | Mobile Guarantee |
| :--- | :--- | :--- |
| `.tactical-select` | `width` | `100%` (expands to full container width) |
| `.tactical-select` | `min-width` | `0` |
| `.segmented` | `width` | `100%` |
| `.segmented button` | `flex` | `1 1 0` (balanced tab distribution) |
| `.segmented button` | `min-width` | `0` |
| `.segmented button` | `justify-content` | `center` |

### 3.8 Sticky Topbar (`.topbar`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `position` | `sticky` | `sticky` | Fixed to top of viewport |
| `top` | `0` | `0` | Locks to top edge |
| `background` | `rgba(7, 9, 11, 0.82)` | `#07090b !important` | **100% opaque, ZERO content bleed-through** |
| `min-height` | `76px` | `56px` | Compact header height |
| `padding` | `0 clamp(24px, 4vw, 48px)`| `calc(10px + env(safe-area-inset-top, 0px)) 16px 10px` | Respects Android status bar notch |
| `z-index` | `20` | `20` | Always above scrolled cards |

### 3.9 Sticky Save Dock (`.tactical-save-dock`)

| Property | Desktop (`> 680px`) | Mobile (`<= 680px`) | Verification Guarantee |
| :--- | :--- | :--- | :--- |
| `position` | `sticky` | `sticky` | Floats at bottom of settings view |
| `bottom` | `0` | `8px` | Hovers above fixed bottom navigation |
| `padding` | `12px 20px` | `10px 14px` | Compact mobile padding |
| `border-radius` | `12px` | `10px` | Rounded pill aesthetic |
| `background` | `rgba(9, 12, 15, 0.92)` | `rgba(9, 12, 15, 0.96)` | High contrast readability |

---

## 4. Invariant Rules

1. **Non-Regressive Desktop Layout**: Desktop media rules ($w > 680\text{px}$) must not be modified in ways that alter desktop wide horizontal flex rows or wide card presentations.
2. **Zero IPC or Functional Impact**: No TypeScript props, hooks, or backend Rust/Kotlin bridge methods shall be changed as part of this contract.
3. **Accessibility Compliance**: All interactive buttons, selects, and steppers must maintain touch targets $\ge 32\text{px}$ in height.
