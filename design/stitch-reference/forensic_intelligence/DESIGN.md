---
name: Forensic Intelligence
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#bdc8d1'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#87929a'
  outline-variant: '#3e484f'
  surface-tint: '#7bd0ff'
  primary: '#8ed5ff'
  on-primary: '#00354a'
  primary-container: '#38bdf8'
  on-primary-container: '#004965'
  inverse-primary: '#00668a'
  secondary: '#c0c1ff'
  on-secondary: '#1000a9'
  secondary-container: '#3131c0'
  on-secondary-container: '#b0b2ff'
  tertiary: '#ffc176'
  on-tertiary: '#472a00'
  tertiary-container: '#f1a02b'
  on-tertiary-container: '#613b00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c4e7ff'
  primary-fixed-dim: '#7bd0ff'
  on-primary-fixed: '#001e2c'
  on-primary-fixed-variant: '#004c69'
  secondary-fixed: '#e1e0ff'
  secondary-fixed-dim: '#c0c1ff'
  on-secondary-fixed: '#07006c'
  on-secondary-fixed-variant: '#2f2ebe'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb960'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  display-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-base:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  code-data:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: -0.01em
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 12px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 16px
  margin-page: 24px
  panel-width: 420px
  density-compact: 8px
  density-comfortable: 16px
---

## Brand & Style

The design system is engineered for high-stakes cybersecurity intelligence, where speed of comprehension and forensic precision are paramount. The personality is authoritative and technical, reflecting a tool built for security analysts who require real-time clarity over aesthetic flourish.

The visual style is **Corporate Modern with Technical Accents**. It utilizes a deep, multi-layered dark theme to reduce eye strain during long shifts, while employing high-contrast "pulsing" indicators for critical threats. The aesthetic borrows from developer tools—clean lines, compact spacing, and monospaced data points—to evoke a sense of systematic reliability. This is a workspace for experts, prioritizing information density and clear hierarchies of urgency.

## Colors

The palette is anchored by a deep charcoal-navy (`#0F172A`) to provide maximum contrast for functional colors. 

- **Primary & Secondary:** Used sparingly for interactive elements, focus states, and primary actions.
- **Surface Tiers:** Use Slate variations to distinguish between the global navigation, main dashboard, and side-panel workspaces.
- **Severity Logic:** This is the core of the system. **Critical (Red)** is reserved exclusively for immediate threats (KEV-listed or high EPSS). **High (Orange)**, **Medium (Yellow)**, and **Low (Blue)** follow a strict hierarchy to guide the analyst's eye. 
- **Text:** High-contrast white for headers, Slate-400 (`#94A3B8`) for secondary metadata and body text to maintain a calm visual field.

## Typography

The typography strategy uses a dual-font approach. **Inter** provides a highly legible, neutral foundation for all UI labels, navigation, and reports. **JetBrains Mono** is introduced for all technical data points, including CVE IDs, IP addresses, hash values, and EPSS scores.

For hierarchy:
- **Headlines:** Use tight letter spacing and semi-bold weights to anchor dashboard sections.
- **Data Grids:** Use `body-sm` for standard cell content and `code-data` for identifiers to create a clear visual distinction between descriptive text and technical keys.
- **Labels:** Use `label-caps` for table headers and section overviews to provide structure without adding visual bulk.

## Layout & Spacing

This design system utilizes a **Fixed-Fluid Hybrid** model. The main navigation and side-panel workspaces have fixed widths to ensure tool consistency, while the central data theater fluidly scales to maximize the visibility of multi-column tables.

- **Grid:** A 12-column grid is used for the primary dashboard view.
- **Density:** The system defaults to a high-density "Compact" mode. Spacing between table rows is minimized (8px) to maximize information per screen inch.
- **Workspaces:** Detail views emerge from the right as a 420px fixed-width "Side-Panel Drawer." This allows analysts to view specific vulnerability details without losing the context of the main list.
- **Breakpoints:** On desktop, the layout is multi-pane. On tablet, the side-panel becomes a full-screen overlay. This system is not intended for mobile phone triage; mobile views reflow to single-column alert feeds only.

## Elevation & Depth

Depth in this design system is communicated through **Tonal Layering** rather than traditional shadows. 

- **Level 0 (Background):** Deepest navy (`#0F172A`), used for the canvas.
- **Level 1 (Cards/Tables):** Slate (`#1E293B`), used for the primary content containers.
- **Level 2 (Navigation/Headers):** A slightly lighter tint or a 1px inner-border (`#334155`) to define boundaries.
- **Level 3 (Modals/Side-Panels):** These use a subtle 10% black drop shadow with a 20px blur to lift them above the data theater, combined with a 1px border in the secondary color to signify active focus.

Outlines are preferred over shadows to maintain a "flat/technical" aesthetic, ensuring the UI feels like a precision instrument rather than a consumer app.

## Shapes

The shape language is **Soft (0.25rem)**. This provides just enough rounding to ensure the UI feels modern and professional, without appearing overly "bubbly" or consumer-oriented.

- **Standard Elements:** Buttons, input fields, and table rows use a 4px radius.
- **Status Badges:** Use a slightly higher radius (8px) to distinguish them as distinct, pill-like "objects" within the data grid.
- **Data Cards:** Use the 4px base radius with a subtle 1px stroke to define the container edges.

## Components

- **Dense Data Tables:** The primary component. Features include `hover-row` highlighting, sticky headers, and "Urgency Signals" (a 4px vertical color bar on the far left of a row indicating severity).
- **Status Badges:** Compact labels for KEV (Known Exploited Vulnerabilities) and EPSS. KEV badges use a high-contrast background; EPSS badges use a percentage-based fills or sparklines.
- **Input Fields:** Dark-themed with a subtle border. The `focus` state uses the Primary Blue color with a 2px outer glow.
- **News Cards:** Used for threat intelligence feeds. These utilize a "split" layout: a small thumbnail or source icon on the left, with a bold headline and "time-ago" metadata on the right.
- **Primary Buttons:** High-contrast, solid fills using the Secondary color for "Take Action" or "Remediate."
- **Ghost Buttons:** Used for secondary filtering and export actions to minimize visual noise.
- **Side-Panel Workspace:** A slide-in container for deep-dive forensics, containing tabbed navigation for "Description," "Affected Assets," and "Timeline."