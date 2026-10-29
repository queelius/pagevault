# pagevault

**Password-protect semi-private content on static sites** – no backend required.

Encrypt sensitive pages and sections while keeping navigation, styling, and public content unchanged. Works with Hugo, GitHub Pages, Netlify, or any static hosting.

## The Problem

You want to publish semi-private content on your static site:
- Technical docs with client-confidential sections
- Blog posts mixing public narratives with private thoughts
- Educational material with solutions behind passwords
- Shared notes that shouldn't be fully public (yet)

Traditional solutions require a backend. pagevault works with *pure static hosting* – your site lives entirely on GitHub Pages, no server needed.

## How It Works

Mark sections with `<pagevault>` tags. pagevault encrypts just those sections while preserving your site's structure, styling, navigation, and scripts.

```html
<header>Public navigation</header>

<pagevault hint="Contact me for the password">
  <h2>Private thoughts on this topic</h2>
  <p>This section is encrypted...</p>
</pagevault>

<footer>Public footer</footer>
```

Visitors see your site normally. When they encounter protected content, a password prompt appears. Once unlocked, the content displays beautifully—and the browser can remember it without storing the password (you control this).

## Quick Start

### 1. Install

```bash
pip install pagevault
```

### 2. Mark content

```html
<pagevault hint="Contact admin for password">
  Private content here
</pagevault>
```

### 3. Create config

```bash
pagevault config init
```

### 4. Encrypt and deploy

```bash
pagevault lock index.html
# Deploy _locked/index.html to your static host
```

That's it! Visitors see a password prompt on protected sections.

## Why pagevault?

| Feature | pagevault | Wrap entire page | CSS hiding | No protection |
|---------|-----------|------------------|-----------|--------------|
| **Mixed public/private** | ✅ | ❌ | ❌ | ❌ |
| **Static hosting** | ✅ | ✅ | ✅ | ✅ |
| **No server** | ✅ | ✅ | ✅ | ✅ |
| **Preserves structure** | ✅ | ❌ | ✅ | ✅ |
| **Real encryption** | ✅ | ✅ | ❌ | ❌ |
| **Viewer plugins** | ✅ | ❌ | ❌ | ❌ |

## Key Features

### For Content Creators
- **Selective encryption**: Mark just what needs protecting
- **HTML structure preserved**: Navigation, scripts, styles stay public
- **Remember-me**: Visitors can skip the prompt on return visits
- **Viewer plugins**: Built-in rendering for images, PDFs, HTML, text, and Markdown

### For Developers
- **CLI-first**: Simple command-line tools, no GUI needed
- **Configuration**: Cascade from CLI args → env vars → YAML → defaults
- **Custom CSS**: Style password prompts to match your site
- **Multi-user**: Encrypt for different users with different passwords
- **Zero runtime deps**: No JavaScript libraries or external services

### For Security
- **AES-256-GCM**: Military-grade AEAD encryption
- **PBKDF2-SHA256**: 310,000 iterations (OWASP recommended)
- **Client-side only**: All processing in browser, no data leaves
- **No tracking**: No analytics, no phone-home, completely stateless

## Common Use Cases

**Hugo Blog**: Publish semi-private posts alongside public content.

**Knowledge Base**: Protect implementation details while sharing approaches.

**Client Work**: Share progress reports with selective access.

**Educational**: Post problems publicly, solutions behind password.

→ [Read more use cases](use-cases.md)

## Getting Started

New to pagevault? Start with [Getting Started](getting-started.md) for a step-by-step walkthrough.

Explore the [CLI Reference](cli-reference.md) for all commands, including `info` (inspect encrypted files), `check` (verify passwords), and `audit` (health check your setup).

Check [Configuration](configuration.md) to customize behavior.

Have questions? See [FAQ](faq.md).

---

Made with ❤️ for static site builders who want privacy without complexity.
