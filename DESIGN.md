# Design System — SentinelForge

## Product Context

- **What this is:** A proof-carrying release gate that detects security defects, creates isolated patch candidates, verifies them, and records the exact evidence behind a release decision.
- **Who it is for:** Platform engineers and security engineers responsible for pre-production release gates.
- **Space:** Application security, release engineering, autonomous security operations.
- **Project type:** Desktop-first operational dashboard with a local API and CLI.
- **Memorable idea:** The proof is the product.

## Aesthetic Direction

- **Direction:** Forensic command instrument.
- **Decoration:** Intentional and restrained. Fine grid lines, evidence rails, and state bars exist to clarify system status rather than imply “cyber” aesthetics.
- **Mood:** Serious, exact, calm under pressure. The interface should feel fit to stop a release and clear enough to defend that decision in a review.
- **References:** XBOW for proof-first offensive security, Wiz for connected risk context, and Snyk for developer-facing remediation. SentinelForge deliberately avoids their marketing language inside the product.

## Typography

- **Display and body:** Instrument Sans. Its narrow, workmanlike forms support dense operational UI without looking like a default admin template.
- **UI and labels:** Instrument Sans, 500-650 weights.
- **Evidence, data, hashes, and code:** IBM Plex Mono with tabular numerals.
- **Loading:** Google Fonts with local sans-serif and monospace fallbacks; the app remains usable offline.
- **Scale:** 12, 13, 14, 16, 20, 28, and 40px. Operational text defaults to 13-14px; large type is reserved for verdicts.

## Color

- **Approach:** Restrained. Neutral surfaces carry structure; semantic colors appear only when they encode evidence or state.
- **Ink:** `#070B0D` — default dark canvas.
- **Panel:** `#0E1417` — primary working surface.
- **Elevated:** `#151D21` — selected rows and evidence panels.
- **Border:** `#29353A` — structural separation.
- **Text:** `#F1F4F2` — primary dark-mode text.
- **Muted:** `#91A09B` — metadata and secondary labels.
- **Bone:** `#F4F1E8` — light-mode canvas.
- **Safe:** `#34D399` — verified patch only.
- **Blocked:** `#FF5A5F` — exploited candidate or denied action.
- **Warning:** `#F5B942` — degraded integration or incomplete proof.
- **Info:** `#55B6FF` — active lifecycle and links.
- **Dark mode:** Default. Light mode is a forensic dossier, not an inverted dark theme: bone canvas, white evidence sheets, dark ink, and slightly reduced semantic saturation.

## Spacing

- **Base unit:** 4px.
- **Density:** Compact but not cramped.
- **Scale:** 2xs 2px, xs 4px, sm 8px, md 12px, lg 16px, xl 24px, 2xl 32px, 3xl 48px.

## Layout

- **Approach:** Grid-disciplined.
- **Grid:** 12 columns above 1100px, 6 columns on tablet, one column below 720px.
- **Max width:** 1600px with a persistent 224px navigation rail on desktop.
- **Primary hierarchy:** Release identity, candidate verdict, patch verdict, evidence timeline, then details.
- **Border radius:** 2px for data surfaces, 4px for controls, 6px for primary panels, full only for tiny status dots.
- **Avoid:** Chat bubbles, uniform stat cards, decorative hacker imagery, glows, purple gradients, bubbly radii, and hidden evidence behind modal dialogs.

## Motion

- **Approach:** Minimal and functional.
- **Easing:** `cubic-bezier(0.2, 0.8, 0.2, 1)` for entry; standard ease-in for exit.
- **Duration:** 80ms micro feedback, 160ms state changes, 240ms panel entry.
- **Rules:** Timeline events may enter once. Verdict color never pulses. Reduced-motion preferences disable all nonessential movement.

## Product States

- **Empty:** Explain the one-command proof loop and focus the repository field.
- **Queued/running:** Show lifecycle separately from security verdicts. Never imply safety while verification is pending.
- **Completed with finding:** Candidate remains blocked; exact patch digest may be safe.
- **No finding:** Candidate may be safe for the checks performed; state coverage limits nearby.
- **Failed:** Preserve successful evidence, name the failed phase, and offer a deterministic retry.
- **Degraded:** Keep integration health separate from candidate and patch verdicts.

## Decisions Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-07-17 | Use a forensic command-instrument direction | Release evidence needs trust and scanability, not conversational AI styling. |
| 2026-07-17 | Reserve red and green for comparative proof | The memorable moment is candidate blocked versus exact patch safe. |
| 2026-07-17 | Make the append-only timeline the main surface | The product differentiates on auditable work, so evidence cannot be secondary UI. |
| 2026-07-17 | Default to dark with a light forensic mode | Dark supports live demo focus; light supports reports and daytime enterprise use. |
