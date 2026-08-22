# Pull Request: Frontend SOC Enhancements & UI Upgrades

## Branch
`feature/soc-ui-enhancements`

## Summary of Changes
This pull request contains all frontend improvements, triage queue styling, AI assistant enhancements, and UI component integrations.

### 1. Triage Queue (`Frontend/app/queue/page.tsx`)
- Tabular Active Threats view with clean columns: Threat / Activity, Severity, Verdict, CVSS Score, Action (removed redundant ID column).
- Centered, single large watermark background layer (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) behind incident groups.
- Translucent rows (`bg-black/25`) to let the watermark show through clearly.
- Integrated `<AnimatedList />` for staggered entrance transitions.
- "Attack Types" threat distribution BarChart on the right column with transparent tooltip cursor.

### 2. Regulatory Compliance & Clocks (`Frontend/app/compliance/page.tsx`, `Frontend/components/soc/primitives.tsx`)
- Side-by-side layout: incident details on the left, regulatory obligation clocks stacked vertically on the right.
- Circular clock dials aligned on the right.
- Overdue deadlines prominently highlighted (`overdue by Xh Ym`).
- Lead card bottom caution callout with alert icon and deadline status.

### 3. Executive Dashboard (`Frontend/app/dashboard/page.tsx`)
- Animated `<CountUp />` counters for violation summary statistics and header badges.
- URL-driven severity filtering (`?severity=critical|high|medium|low|all`) to strictly isolate categories when clicked.

### 4. Agentic AI Assistant (`Frontend/app/ai/page.tsx`)
- Integrated `<TextType />` typing effect from React Bits in the center hero state.
- One-click interactive prompt starters that automatically submit queries.
- Cleaned input border and focus ring styling.
- Reset conversation button.

### 5. UI & Global Polish
- **Global Particle Interaction**: Integrated `<ClickSpark />` with vibrant green (`#22c55e`) particles on every click across the app.
- **Dock Navigation**: `<Dock />` sidebar integration.
- **Data Repair**: `repair_campaigns.py` script to synthesize missing correlated campaigns (`CMP-002`, `CMP-003`).

### 6. Dependencies (`Frontend/package.json`)
- Added `gsap` (for TextType typing animations)
- Added `motion` / `framer-motion` (for AnimatedList transitions)
