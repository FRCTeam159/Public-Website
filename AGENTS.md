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
  <a href="/" aria-label="Home"><img src="assets/logo.png" ... /><span>Alpine Robotics</span></a>
  <nav aria-label="Primary">
    <ul>
      <li><a href="/">Home</a></li>
      <li><a href="page.html">Label</a></li>
    </ul>
  </nav>
</header>
```
Add new top-level pages as another `<li><a>` here. Styling (sticky bar,
hover states, spacing) comes from `header > a`, `header > nav > ul`,
`header > nav > ul > li > a`.

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
consistent spacing. Use this for any list of discrete items (news, events,
sponsor tiers, resource links) — don't build a new list/grid pattern for
that; reshape the content into `article` cards instead.

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
