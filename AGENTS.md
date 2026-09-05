# AGENTS.md — Alpine Robotics Public Website

This file is for AI coding assistants (Claude Code, Antigravity, or any other
CLI/IDE agent) working in this repo, and for the students using them. Read it
before touching `site/`.

## What this project is

A static, no-build HTML/CSS site for an FRC team. There is no framework, no
bundler, no npm/package.json, and no templating engine. Pages are plain
`.html` files in `site/`, styled by the single shared `site/styles.css`.

- `site/index.html` — the home page
- `site/styles.css` — the **only** stylesheet, shared by every page
- `site/assets/` — images/icons

Pushing to the `Staging` branch deploys to GitHub Pages automatically (see
`README.md`). There is no other build step.

## The core convention: structure drives style

This is the most important thing in this repo, and the reason this file
exists.

**`styles.css` is written and maintained by the mentor (and by agents working
with the mentor). Students are not expected to write or edit CSS.** Instead,
students write plain semantic HTML that follows the existing structural
patterns below, and the correct styling is applied automatically.

This works because `styles.css` deliberately styles **structural
relationships**, not classes. Look at the selectors already in the file:

```css
header > a
header > nav > ul > li > a
main > section:has(> figure)
main > section:has(> figure) > figure > figcaption
main > section:has(> article)
main > section:has(> article) > article
footer > p
```

There is no `class="..."` anywhere in `index.html`. The CSS keys off **tag
names and parent/child position** (including `:has()` to detect what kind of
child a `<section>` contains). That means:

- A student adds a `<section>` containing a `<figure>` → they get a full-bleed
  hero/banner treatment for free.
- A student adds a `<section>` containing `<article>` elements → they get the
  bordered "card" treatment, spacing, and max-width container for free.
- A student adds an `<li><a>` inside `header > nav > ul` → it gets nav-link
  styling and hover state for free.

Students learn HTML semantics and get a professional-looking result without
touching a stylesheet or memorizing class names. That is the pedagogical
point — protect it.

## Rules for agents editing this repo

1. **Never add `class` or `id` attributes, inline `style=""`, or `<style>`
   blocks to make something look right.** If a page doesn't look right, the
   fix is either (a) restructure the HTML to match an existing pattern below,
   or (b) add a new structural rule to `styles.css` — not a one-off override
   in the markup.
2. **Reuse the patterns documented below exactly** (same tag nesting, same
   element order) rather than inventing a new shape for the same kind of
   content. Consistency across pages is what makes the "structure = style"
   contract hold.
3. **If a genuinely new visual pattern is needed** (something no existing
   selector covers), add a new structural selector to `styles.css` following
   the same tag/`:has()`-based approach, and call it out clearly as a new
   pattern in the PR/commit description so the mentor can review it. Do not
   quietly bolt on a class-based override next to the structural rules — the
   two approaches don't mix well and defeat the point for students.
4. **Keep `styles.css` selectors structural, not presentational.** Prefer
   `main > section:has(> ...)` style selectors over introducing utility
   classes like `.card` or `.hero`.
5. New pages must include the same `<head>` boilerplate, `<header>`, and
   `<footer>` as `index.html` (see below) so nav and footer styling applies
   uniformly.

## Existing structural patterns (as of this writing)

### Page shell
Every page repeats this shape from `index.html`:
```html
<head>
  <!-- meta, title, description -->
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="styles.css" />
  <link rel="icon" href="assets/favicon.webp" />
</head>
<body>
  <header>...</header>
  <main>...</main>
  <footer>...</footer>
  <script>/* sets #year for the copyright line */</script>
</body>
```

### Header / nav
```html
<header>
  <a href="index.html" aria-label="Home"><img src="assets/logo.png" ... /><span>Alpine Robotics</span></a>
  <nav aria-label="Primary">
    <ul>
      <li><a href="index.html">Home</a></li>
      <li><a href="page.html">Label</a></li>
    </ul>
  </nav>
</header>
```
Add new top-level pages as another `<li><a>` here. Styling (sticky bar,
hover states, spacing) comes from `header > a`, `header > nav > ul`,
`header > nav > ul > li > a`.

**Use `href="index.html"` for Home, never `href="/"`.** This site is
currently served from a path prefix (`/Public-Website/`, and one level
deeper again for PR previews, `/Public-Website/pr-preview/pr-<N>/`), so an
absolute root link 404s. A relative filename resolves correctly no matter
how deep the site is nested — the same reasoning applies to every link and
asset path in this repo (see how `team.html`, `assets/logo.png`, etc. are
all written as relative paths already).

### Hero / banner section
Trigger: a `<section>` whose direct child is a `<figure>`.
```html
<section>
  <figure>
    <img src="assets/whatever.jpg" alt="..." decoding="async" loading="eager" />
    <figcaption>
      <h1>Headline</h1>
      <p>Subheadline</p>
    </figcaption>
  </figure>
</section>
```
Gives: full-bleed image, dark gradient overlay behind the caption, responsive
type sizing. Use for page-top banners, not just the homepage hero.

### Content / news-card section
Trigger: a `<section>` whose direct children include `<article>` elements.
```html
<section>
  <h2>Section Title</h2>
  <article>
    <h4>Card title</h4>
    <p>Card body.</p>
  </article>
  <article>...</article>
</section>
```
Gives: centered max-width container, bordered/shadowed white cards with
consistent spacing. Use this for any list of discrete news/event items —
don't build a new grid pattern for that; reshape the content into `article`
cards instead. (Sponsor tiers and blog-style posts have their own more
specific patterns below — use those instead for that kind of content.)

### Carousel section
Trigger: a `<section>` whose direct child is a `<ul>` of `<li><img></li>`.
```html
<section>
  <ul>
    <li><img src="assets/whatever.jpg" alt="..." decoding="async" loading="eager" /></li>
    <li><img src="assets/whatever.jpg" alt="..." decoding="async" loading="lazy" /></li>
  </ul>
</section>
```
Gives: a full-bleed, horizontally swipeable image strip using pure CSS
scroll-snap — no JavaScript. Used for the Team and Resources page banners
(`site/team.html`, `site/resources.html`). Add/remove `<li>` slides for more
or fewer images; each `<li>` must contain exactly one `<img>` and nothing
else. Follow this section with a plain `<section><h1>...</h1><p>...</p></section>`
for body copy — it needs no special markup, the base `main > section` rule
already centers and pads it.

### Blog alternation section
Trigger: inside a `main > section:has(> article)`, an `<article>` whose
first child is a `<figure>`. Builds on the card pattern above (still gets
the white/bordered/shadowed card), and additionally lays the figure and a
text block side by side, alternating sides every other `<article>`.
```html
<section>
  <h2>Section Title</h2>
  <article>
    <figure><img src="assets/whatever.jpg" alt="..." decoding="async" loading="lazy" /></figure>
    <div>
      <h3>Post title</h3>
      <p>Post body.</p>
    </div>
  </article>
  <article>...</article>
</section>
```
Used for the Outreach page's "Recent Community Involvement" posts
(`site/outreach.html`) and the Robot page's season-by-season history
(`site/robot.html`). The `<div>` around the heading/paragraph is just a
grouping container (no class/id) so the two can act as one flex column
next to the figure — add new posts as another `<article>` in this exact
shape; the 1st/3rd/5th... post shows image-left, the 2nd/4th/6th... shows
image-right, automatically.

### Tiered list section
Trigger: a `<section>` whose direct children are nested `<section>`s, each
containing a heading and a `<ul>` of plain-text `<li>` items.
```html
<section>
  <section>
    <h2>Title Sponsors</h2>
    <ul><li>Sponsor Name</li></ul>
  </section>
  <section>
    <h2>Primary Sponsors</h2>
    <ul><li>Sponsor Name</li></ul>
  </section>
  <section>
    <h2>Helping Hands</h2>
    <ul><li>Sponsor Name</li></ul>
  </section>
</section>
```
Gives: rows of sized "chip" pills — the first nested `<section>` renders
largest, each one after progressively smaller. **Tier order in the markup
controls size** (biggest tier first), not the heading text — so keep the
most prominent tier's `<section>` first. Used for `site/sponsors.html`.

### Schedule table section
Trigger: a `<section>` whose direct child is a `<table>`.
```html
<section>
  <h2>Meeting Schedule</h2>
  <table>
    <thead><tr><th scope="col">Day</th><th scope="col">Time</th></tr></thead>
    <tbody><tr><td>Monday</td><td>4:00 – 6:00 PM</td></tr></tbody>
  </table>
</section>
```
Gives: a clean, full-width, bordered-row table. Used for the meeting
schedule on `site/contact.html`. Use a real `<table>` (with `<thead>`) for
any tabular/schedule data rather than faking rows with `<div>`s.

### Contact details section
Trigger: a `<section>` whose direct child is a `<dl>`.
```html
<section>
  <h2>Location &amp; Contact</h2>
  <dl>
    <dt>Address</dt><dd>...</dd>
    <dt>Email</dt><dd><a href="mailto:...">...</a></dd>
  </dl>
</section>
```
Gives: label/value pairs laid out in two aligned columns (stacks to one
column on mobile). Used for address/email/phone on `site/contact.html`.
Use this for any label→value list; don't reshape that kind of content into
`article` cards or a table.

### Footer
```html
<footer>
  <p>© <span id="year"></span> Alpine Robotics. All rights reserved.
    <a href="privacy.html">Privacy</a> · <a href="code-of-conduct.html">Code of Conduct</a>
  </p>
</footer>
```
Keep footer links appended to this same `<p>`.

### Design tokens
Colors and layout constants live as CSS custom properties on `body` in
`styles.css` (`--brand`, `--brand-2`, `--ink-muted`, `--bg-soft`, `--border`,
`--maxw`). If new HTML needs a color, reference one of these tokens in a
structural CSS rule rather than hardcoding a hex value in a new class.

## When in doubt

If a task requires deviating from these patterns, stop and flag it rather
than improvising a one-off class or inline style — surface it for the mentor
to fold into `styles.css` as a new shared pattern.
