# FAQ

## Basics

**Q: What does pagevault do?**
A: pagevault encrypts marked sections of HTML files so visitors need a password to view them. Everything else (navigation, styling, public content) stays visible. Encryption happens on your computer; decryption happens in visitor's browser.

**Q: Do I need a server?**
A: No. pagevault works with pure static hosting: GitHub Pages, Netlify, Vercel, or any static host. All decryption happens client-side in the browser.

**Q: How is it different from hiding content with CSS?**
A: CSS hiding is cosmetic – the encrypted content is still in the HTML source and can be seen by inspecting the page. pagevault uses real encryption (AES-256-GCM), so content is unreadable without the password.

**Q: Is it secure?**
A: Yes. pagevault uses AES-256-GCM (military-grade encryption) and PBKDF2-SHA256 with 310,000 iterations (OWASP standard). All processing is client-side; no data leaves your browser. See [Security](security.md) for details.

**Q: Can't attackers just crack the encryption?**
A: AES-256 is cryptographically unbreakable with current technology. The only way to access encrypted content is knowing the password. This is why **strong passwords matter** – weak passwords can be guessed.

## Installation & Setup

**Q: What are the system requirements?**
A: Python 3.10+. Install via pip: `pip install pagevault`

**Q: Where does pagevault output files?**
A: By default:
- Encrypted: `_locked/`
- Decrypted: `_unlocked/`

Use `-d` flag to specify custom directory: `pagevault lock page.html -d public/encrypted/`

**Q: Do I need to commit `.pagevault.yaml` to version control?**
A: **No!** Add it to `.gitignore`. It contains passwords.

```bash
echo ".pagevault.yaml" >> .gitignore
```

**Q: What if I lose my `.pagevault.yaml`?**
A: You can't recover encrypted files without the password. Back it up securely (password manager, encrypted drive, KMS system).

## Usage

**Q: Can I encrypt an entire website?**
A: Yes, in two ways:

1. **Individual files**: `pagevault lock site/ -r` encrypts each HTML file's marked sections
2. **Single bundle**: `pagevault lock mysite/ --site -o mysite.html` bundles entire site as one encrypted HTML file

**Q: Can I mark content with CSS selectors instead of `<pagevault>` tags?**
A: Yes! Use `pagevault mark`:

```bash
pagevault mark page.html -s ".private"  # Marks all elements with class="private"
pagevault mark page.html -s "#secret"   # Marks element with id="secret"
```

**Q: How do I encrypt only certain elements?**
A: Use selectors:

```bash
pagevault lock page.html -s ".private" -s "#secret"
```

Or manually wrap in `<pagevault>` tags.

**Q: Can I update encrypted content?**
A: Yes:

```bash
pagevault unlock _locked/page.html  # Decrypt to _unlocked/page.html
# Edit _unlocked/page.html
pagevault lock _unlocked/page.html  # Re-encrypt
```

**Q: What if I change the password?**
A: Edit `.pagevault.yaml` and re-encrypt:

```bash
# Change password in .pagevault.yaml
pagevault lock _locked/ -r  # Re-encrypts everything with new password
```

Old files become inaccessible. Keep backup of previous `.pagevault.yaml` if you need to decrypt old files.

## Passwords & Security

**Q: What makes a good password?**
A: Strong passwords have:
- At least 16 characters (longer is better)
- Mix of uppercase, lowercase, numbers, symbols
- No dictionary words or personal information
- Uniqueness (not reused elsewhere)

**Recommendation:** Use a password manager (1Password, Bitwarden, KeePass) to generate and store passwords.

**Q: Can I use environment variables instead of `.pagevault.yaml`?**
A: Yes:

```bash
export PAGEVAULT_PASSWORD="my-password"
pagevault lock page.html
```

Good for CI/CD systems (GitHub Actions, GitLab CI).

**Q: How do I share encrypted content?**
A: Send HTML and password separately:

```bash
# Send HTML file via email attachment, Slack, etc.
# Send password via different channel (separate email, Signal, etc.)
```

This way, if one channel is compromised, attacker has only half.

**Q: Can multiple people have different passwords?**
A: Yes, use multi-user mode:

```yaml
users:
  alice: "alice-password"
  bob: "bob-password"
```

Encrypt with this config:
```bash
pagevault lock page.html
```

Both alice and bob can decrypt with their password.

**Q: What if I forget the password?**
A: You'd need to:
1. Delete encrypted file
2. Generate new password (edit `.pagevault.yaml` or `pagevault config init`)
3. Re-encrypt from original

There's no "forgot password" recovery. Treat passwords like important credentials.

## Integration

**Q: Does pagevault work with Hugo?**
A: Yes! Workflow:

```bash
hugo -o build/              # Generate site
pagevault mark build/ -r    # Mark content
pagevault lock build/ -r    # Encrypt
# Deploy build/_locked/
```

Or in Hugo config as post-build hook.

**Q: Does it work with Next.js/Gatsby/other generators?**
A: Yes! pagevault processes HTML files. Works with any static site generator that outputs HTML.

**Q: Can I use pagevault with GitHub Pages?**
A: Yes! Deploy encrypted files to gh-pages branch:

```bash
pagevault lock docs/ -r
git add docs/_locked/
git push origin gh-pages
```

GitHub Pages serves HTTPS by default, which is required.

**Q: Does pagevault work with Netlify?**
A: Yes! Upload encrypted files normally. Netlify provides HTTPS automatically.

## Multi-User & Advanced

**Q: How does multi-user encryption work?**
A: Each encrypted file includes encrypted keys for all users. When decrypting:

1. Visitor enters password
2. pagevault derives key from password + salt
3. Uses key to decrypt content

Different passwords = different keys, but all can decrypt the same content.

**Q: Can I rotate multi-user passwords?**
A: Yes:

```bash
pagevault config user passwd alice  # Change alice's password
pagevault sync _locked/ -r          # Re-encrypt with new password
```

**Q: Can I encrypt for different users differently?**
A: Not directly. All users share the same content; they just have different passwords.

If you want *different content* for different users, encrypt separately:
```bash
pagevault lock page.html -u alice -p "alice-pw"  # Creates file encrypted for alice
pagevault lock page.html -u bob -p "bob-pw"      # Creates file encrypted for bob
```

## Browser & Client-Side

**Q: What browsers are supported?**
A: All modern browsers that support WebCrypto API:
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+
- Mobile browsers (iOS Safari, Chrome Mobile, etc.)

**Q: Can I customize the password prompt?**
A: Yes! Use custom CSS:

```bash
pagevault lock page.html --css custom.css
```

Or configure in `.pagevault.yaml`:

```yaml
template:
  title: "Premium Content"
  button_text: "Unlock Article"
  hint: "See newsletter for password"
```

**Q: Can visitors remember their password?**
A: Yes, configurable:

```yaml
defaults:
  remember: "ask"      # "none", "session", "local", "ask"
  remember_days: 30    # For "local" mode
```

- `"none"`: Always prompt
- `"session"`: Forget when the tab closes
- `"local"`: Remember on this device (expires after remember_days)
- `"ask"`: Let visitor choose

The password itself is never stored, only a key that opens pages locked with
the same password and salt. See [Security](security.md#remembered-passwords).

**Q: Can I logout visitors?**
A: Yes, use URL fragment:

```
https://example.com/page.html#pagevault_logout
```

Clears every remembered key for that site from the browser.

## Inspection & Verification

**Q: How can I inspect an encrypted file without the password?**
A: Use the `info` command:

```bash
pagevault info encrypted.html
```

This shows encryption metadata (algorithm, key count, ciphertext size, viewers, etc.) without decrypting content.

**Q: How can I verify a password without decrypting the whole file?**
A: Use the `check` command:

```bash
pagevault check encrypted.html -p "test-password"
```

Exit code 0 means correct, 1 means incorrect. Useful for scripting.

**Q: How do I audit my encryption setup?**
A: Use the `audit` command:

```bash
pagevault audit
```

This checks password strength, salt quality, config hygiene (e.g., `.pagevault.yaml` in `.gitignore`), and file integrity.

## Viewer Plugins

**Q: What are viewer plugins?**
A: When you wrap non-HTML files (PDFs, images, etc.) with `pagevault lock`, viewer plugins provide in-browser rendering after decryption. Built-in viewers handle images, PDFs, HTML, plain text, and Markdown.

**Q: Can I add custom viewers?**
A: Yes. Viewer plugins use Python entry points. Install a package that registers under the `pagevault.viewers` group, and it will be discovered automatically at lock time. See the [Security](security.md) page for the plugin trust model.

**Q: Can I disable specific viewers?**
A: Yes, use the `viewers` section in `.pagevault.yaml`:

```yaml
viewers:
  pdf: false      # Disable PDF viewer
  markdown: true  # Explicitly enable Markdown viewer
```

If the `viewers` section is absent, all discovered viewers are enabled.

## Troubleshooting

**Q: Why isn't my selector working?**
A: Check that your CSS selector is valid and matches elements:

```bash
# Test in browser DevTools console
document.querySelectorAll(".private")

# Make sure HTML has matching elements
pagevault mark page.html -s ".private"
```

**Q: Why is the encrypted file so large?**
A: pagevault includes the decryption logic (Web Component + JavaScript) in each file. Size: typically 50-150 KB depending on dependencies.

You can minimize with `--minify` (coming soon).

**Q: Can I encrypt multiple times (composable encryption)?**
A: Yes! Decrypt→re-encrypt is fully supported:

```bash
pagevault lock page.html -p "password1"      # Lock once
pagevault lock _locked/page.html -p "password2"  # Lock again
# Now need both passwords to decrypt (in reverse order)
```

**Q: Does pagevault work offline?**
A: Encryption (CLI) requires Python but is offline.

Decryption (browser) works completely offline. Visitors can save encrypted HTML and open locally.

**Q: Can I inspect encrypted content in browser DevTools?**
A: Yes, but it's encrypted! In HTML source, encrypted content appears as Base64-encoded ciphertext. Without the password, it's unreadable.

## Performance

**Q: How fast is encryption?**
A: PBKDF2-SHA256 with 310,000 iterations takes ~100-200ms per file on modern hardware. Should be fast enough for most workflows.

**Q: How fast is decryption in browser?**
A: AES-256-GCM decryption is ~1-5ms per file using browser's native WebCrypto. Nearly instant for visitors.

**Q: Does large encrypted files slow down the page?**
A: Encrypted data size is slightly larger (due to authentication tag), but performance impact is minimal. Page loads normally; decryption happens when needed.

## Legal & Compliance

**Q: Is pagevault open source?**
A: Yes, MIT license. Free to use commercially and privately.

**Q: Can I use pagevault in my company?**
A: Yes, MIT license permits commercial use. No license fees or restrictions.

**Q: Does pagevault comply with GDPR/CCPA?**
A: pagevault doesn't collect or store any user data. All processing is client-side. You're responsible for privacy policies and disclosures on your site.

**Q: Can I use pagevault for payment-protected content?**
A: pagevault encrypts content, but doesn't handle payments. You'd need:
1. Payment processor (Stripe, Gumroad, etc.)
2. Authentication system
3. pagevault to encrypt delivery

Example: Gumroad handles payment, sends password to customer, customer uses password to unlock pagevault-protected content.

---

Can't find your question? Check:
- [Getting Started](getting-started.md)
- [CLI Reference](cli-reference.md)
- [Configuration](configuration.md)
- [Security](security.md)

Still have questions? Open an issue on GitHub.
