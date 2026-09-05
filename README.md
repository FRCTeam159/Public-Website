Welcome to the repository hosting the code for the Alpine Robotics website!

# How to develop

See `AGENTS.md` for the site's structure and CSS conventions before making
changes — this applies whether you're a student, a mentor, or an AI coding
assistant.

# Contribution & deployment workflow (trial)

We're trialling a PR-based workflow before pointing the team's real domain
at GitHub Pages. Once this is proven out, the plan is to switch the domain
over and treat GH Pages as the permanent host.

- **Open a PR** → a GitHub Action automatically builds and deploys a preview
  of that PR to its own URL, and comments on the PR with the link once it's
  live:
  `https://frcteam159.github.io/Public-Website/pr-preview/pr-<PR number>/`
  Anyone can open that link to see the PR's changes rendered live, no local
  setup required.
- **Merging requires 2 approvals**, and at least one of them must come from
  a mentor:
  - [@Isaak-Malers](https://github.com/Isaak-Malers)
  - [@tipsmiller](https://github.com/tipsmiller)
  - [@dwsindorf](https://github.com/dwsindorf)
- **Merging to `main`** automatically deploys to the live site:
  https://frcteam159.github.io/Public-Website/

This replaces the old `Staging`-branch deploy process, which pushed to the
same URL as the live site — the two are being consolidated into the single
PR-preview → merge-to-deploy flow above.
