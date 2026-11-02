# pagevault

**Password-protect semi-private content on static sites** – ideal for Hugo blogs, GitHub Pages, or any static hosting.

Encrypt sensitive pages and sections while keeping navigation, styling, and public content unchanged. Deploy to GitHub Pages, Netlify, or any static host without a backend.

## The Problem

You want to publish semi-private content on your static site:
- Technical docs with client-confidential sections
- Blog posts mixing public narratives with private thoughts
- Educational material with solutions behind passwords
- Shared notes that shouldn't be fully public (yet)

Traditional solutions require a backend. pagevault works with *pure static hosting* – your site is entirely on GitHub Pages or equivalent, no server needed.

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

Visitors see your site normally. When they encounter protected content, a password prompt appears. Once unlocked, the content displays beautifully. The browser can remember an unlocked page (configurable), without storing the password.

## Why pagevault?

| Feature | pagevault | Wrap entire page | Hide with CSS | No protection |
|---------|-----------|------------------|---------------|---------------|
| **Mixed public/private** | ✅ | ❌ | ❌ | ❌ |
| **Static hosting** | ✅ | ✅ | ✅ | ✅ |
| **No server** | ✅ | ✅ | ✅ | ✅ |
| **Preserves structure** | ✅ | ❌ | ✅ | ✅ |
| **Real encryption** | ✅ | ✅ | ❌ | ❌ |
| **Viewer plugins** | ✅ | ❌ | ❌ | ❌ |

## Quick Start

### 1. Install

```bash
pip install pagevault
```

### 2. Mark content in your HTML

```html
<!-- Mark manually or use the CLI -->
<pagevault>Private content here</pagevault>
```

Or auto-mark sections:

```bash
pagevault mark page.html -s "#private" --hint "Contact admin"
```

### 3. Initialize config

```bash
pagevault config init
# Creates .pagevault.yaml with a generated password
# Add to .gitignore!
```

### 4. Encrypt and deploy

```bash
pagevault lock index.html site/*.html -d _locked/
# Deploy _locked/ to your static host
```

Visitors see password prompts on protected sections. Share the password however you like – via email, in docs, Discord, etc.

## Real-World Use Cases

### Hugo Blog
```bash
# Mark semi-private blog posts
pagevault mark content/posts/*.md --selector ".private"

# Generate locked HTML during build
hugo -o build/
pagevault lock build/posts/ -r --css styles/pagevault.css

# Deploy to GitHub Pages
git add build/
git commit -m "Publish semi-private posts"
git push
```

### Shared Knowledge Base
```bash
# Protect implementation details in public docs
pagevault lock docs/ -r --hint "See team wiki for password"
# Upload to Netlify
```

### Client Projects
```bash
# Share progress with selective access
pagevault lock status-page.html -p "$CLIENT_PASSWORD"
# Send link + password to stakeholders only
```

## Features

### For Users
- **Auto-prompt**: Password prompt appears automatically (optional)
- **Remember-me**: Reopen pages without a prompt (per tab or per device); stores a non-extractable key, never the password
- **Clean logout**: `#pagevault_logout` forgets remembered keys
- **Event hooks**: JavaScript can react to decryption

### For Developers
- **Selective encryption**: Mark just what needs protecting
- **HTML structure preserved**: Navigation, scripts, styles stay public
- **Custom CSS**: Use your own styles for the password prompt
- **Multi-user encryption**: Encrypt for different users with different passwords
- **Viewer plugins**: Built-in viewers for images, PDFs, HTML, text, and Markdown
- **Configuration cascade**: Command-line > env vars > .pagevault.yaml > defaults
- **Web Crypto API**: Same encryption as modern browsers use

## Security

- **AES-256-GCM**: Military-grade AEAD encryption
- **PBKDF2-SHA256**: 310,000 iterations for key derivation (OWASP recommended)
- **WebCrypto compatible**: Uses standard browser APIs, no custom crypto
- **Stateless**: No tracking, no analytics, all processing on-client

## Installation

```bash
pip install pagevault
# or
pip install git+https://github.com/queelius/pagevault.git
```

Requires Python 3.10+.

## CLI Reference

```bash
# Lock (encrypt marked regions or entire files)
pagevault lock page.html                  # HTML: encrypt marked regions
pagevault lock report.pdf                 # PDF: wrap entire file
pagevault lock site/                      # All files in directory
pagevault lock site/ --site               # Bundle as encrypted site
pagevault lock page.html -s "#secret"     # Encrypt only #secret element
pagevault lock page.html --pad            # Pad content to prevent size leakage

# Unlock (decrypt, returns to marked state)
pagevault unlock _locked/page.html
pagevault unlock _locked/ -r
pagevault unlock report.pdf.html --stdout -p "$SECRET" > report.pdf

# Inspect & verify
pagevault info encrypted.html             # Show metadata without password
pagevault check encrypted.html -p "pw"    # Verify password (exit 0=correct)
pagevault audit                           # Health check config & passwords

# Mark (add encryption tags)
pagevault mark page.html                  # Wrap entire body
pagevault mark page.html -s ".private"    # Wrap matching elements

# Config
pagevault config init                     # Create .pagevault.yaml
pagevault config show                     # Display current config
pagevault config where                    # Find config file

# Sync (re-encrypt for user changes)
pagevault sync _locked/ -r                # Update after password change
```

## Configuration

Create `.pagevault.yaml` in your project root (add to `.gitignore`!):

```yaml
# Encryption
password: "your-strong-passphrase"         # Required
salt: "auto-generated"                     # Regenerated on config init

# UI defaults
defaults:
  remember: "ask"                          # "none", "session", "local", "ask"
  remember_days: 0                         # 0 = no expiration
  auto_prompt: true                        # Show password prompt on load

# Styling
template:
  title: "Protected Content"               # Shown in prompt
  button_text: "Unlock"
  error_text: "Incorrect password"
  hint: "Contact admin for password"       # Default hint

# Multi-user
users:
  alice: "alice-password"
  bob: "bob-password"
```

Or use environment variable:
```bash
export PAGEVAULT_PASSWORD="your-password"
pagevault lock page.html
```

## Architecture

**Workflow:**
```
CLI (cli.py)
  ↓
Config (config.py) – cascade: args > env > .pagevault.yaml > defaults
  ↓
Parser (parser.py) – HTML manipulation with BeautifulSoup/lxml
  ↓
Crypto (crypto.py) – WebCrypto-compatible AES-256-GCM
  ↓
Wrap (wrap.py) – Bundle files/sites into encrypted HTML
  ↓
Template (template.py) – Inject Web Component + JS runtime
```

**Self-contained output:** Every encrypted HTML file includes the decryption logic, no external dependencies at runtime.

## Contributing

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Test
pytest tests/ -v --cov=pagevault

# Lint
ruff check src/ tests/
ruff format src/ tests/
```

## License

MIT – See LICENSE for details.

## FAQ

**Q: Is this safe?**
A: Yes. Uses AES-256-GCM and PBKDF2-SHA256 with 310k iterations. All processing is client-side, no data leaves your browser.

**Q: Can I share the encrypted files publicly?**
A: Yes! Encryption is strong. The password is what you control – share it however you like (email, docs, Discord, etc.) or not at all.

**Q: Does this work with Hugo/Next.js/Gatsby?**
A: Yes! Any static site generator. pagevault processes HTML files after your generator creates them.

**Q: Can multiple people have different passwords?**
A: Yes! Use the `users` config to encrypt for multiple users independently.

**Q: What if I forget the password?**
A: You'd need to re-encrypt with a new password. Store passwords safely! Consider a password manager.

**Q: Can I update encrypted content?**
A: Decrypt with `pagevault unlock`, edit the HTML, then re-encrypt with `pagevault lock`.

---

Made with ❤️ for static site builders who want privacy without complexity.
