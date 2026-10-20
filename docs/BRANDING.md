# Sentinel visual identity and dashboard design tokens

The dashboard uses the local Sentinel SVG wordmark and icon. The product's
Python package and CLI remain `sshlog-analyzer` for compatibility. No logo
asset loads fonts, scripts, or resources from a remote origin.

## Tokens

- Background: `#f4f7fa`
- Surface: `#ffffff`
- Primary: `#087e8b`
- Main text: `#1d2a3a`
- Severity/risk: Streamlit's semantic red, orange, yellow, and green badge colors
- Typography: system sans-serif
- Spacing: native Streamlit layout with aligned columns and standard component gaps
- Tables: native Streamlit dataframe with visible headers and responsive width
- Form controls: native Streamlit widgets with their keyboard and focus behavior
- Borders/radii: Streamlit light-theme defaults

The design intentionally avoids custom JavaScript, remote fonts, animation,
and external style libraries. At this stage, no custom breakpoint stylesheet
or screenshot artifact is maintained. Check narrow and desktop browser layouts
when validating an interface change.
