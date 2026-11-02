# Getting Started with pagevault

This guide walks you through encrypting your first HTML file.

## Installation

```bash
pip install pagevault
```

Requires Python 3.10 or higher.

## Basic Workflow

### 1. Create an HTML File

Create `example.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>My Page</title>
    <style>
        body { font-family: sans-serif; margin: 2rem; }
    </style>
</head>
<body>
    <header>
        <h1>Welcome</h1>
        <p>This is public content everyone can see.</p>
    </header>

    <main>
        <h2>Public Section</h2>
        <p>More public information here.</p>

        <h2>Protected Section</h2>
        <pagevault hint="Contact me for the password">
            <p>This content is encrypted. Visitors need the password to see it.</p>
            <p>Only the section inside &lt;pagevault&gt; gets encrypted.</p>
            <p>Everything else (header, navigation, scripts) stays public.</p>
        </pagevault>
    </main>

    <footer>
        <p>Public footer.</p>
    </footer>
</body>
</html>
```

### 2. Initialize Configuration

Create `.pagevault.yaml` in your project:

```bash
pagevault config init
```

This generates a configuration file with:
- A random password (save this somewhere safe!)
- A salt for key derivation
- Default settings

Check the generated config:

```bash
pagevault config show
```

### 3. Encrypt the File

```bash
pagevault lock example.html
```

This creates `_locked/example.html` with the marked content encrypted.

### 4. Open in Browser

Open `_locked/example.html` in your browser. You'll see:

1. The public header, footer, and unencrypted sections display normally
2. The protected section shows a password prompt
3. Enter the password from `.pagevault.yaml`
4. Content decrypts and displays beautifully

## Understanding the Workflow

**Before encryption:**
```
example.html
├── Header (public)
├── Navigation (public)
├── <pagevault> section (encrypted by pagevault)
└── Footer (public)
```

**After encryption:**
```
_locked/example.html
├── Header (public)
├── Navigation (public)
├── <pagevault> (now encrypted AES-256-GCM)
└── Footer (public)
└── + Web Component + JS runtime (decryption logic)
```

## Customizing Encryption Markers

By default, pagevault encrypts what you mark with `<pagevault>` tags. You can be more selective:

### Encrypt by CSS Selector

Mark specific elements using CSS selectors:

```bash
pagevault mark example.html -s ".private" --hint "Staff only"
```

This wraps all elements with `class="private"` in `<pagevault>` tags.

### Encrypt Multiple Sections

```bash
pagevault mark example.html -s ".private" -s "#secret"
```

### Auto-mark Entire Body

If your HTML has no `<pagevault>` tags, pagevault marks the entire body:

```bash
pagevault lock example.html
# Encrypts entire <body> content
```

Unencrypted content: `<head>`, navigation, external scripts.

## Managing Passwords

### Change Password

Edit `.pagevault.yaml` and change the password:

```yaml
password: "new-strong-password"
```

Re-encrypt files:

```bash
pagevault lock example.html
```

This creates a new encrypted version with the new password.

### Use Environment Variable

Instead of storing password in `.pagevault.yaml`, use an environment variable:

```bash
export PAGEVAULT_PASSWORD="my-secret-password"
pagevault lock example.html
# Doesn't require .pagevault.yaml
```

### Override Password at Command Line

```bash
pagevault lock example.html -p "temporary-password"
```

## Unlocking (Decrypting)

To restore the original file (with `<pagevault>` tags still in place):

```bash
pagevault unlock _locked/example.html
```

Creates `_unlocked/example.html` with content decrypted but still marked.

## Working with Multiple Files

Encrypt all HTML files in a directory:

```bash
pagevault lock src/pages/ -r
# Processes all .html files recursively
# Output: _locked/src/pages/
```

Specify output directory:

```bash
pagevault lock src/pages/ -r -d public/encrypted/
# Output: public/encrypted/
```

## Hugo Integration

If you're building a Hugo blog:

1. Create content with `<pagevault>` markers
2. Build your site: `hugo -o build/`
3. Encrypt built HTML: `pagevault lock build/posts/ -r`
4. Deploy from `build/_locked/`

Example script:

```bash
#!/bin/bash
hugo -o build/
pagevault lock build/posts/ -r --css assets/pagevault.css
rsync -av build/_locked/ deploy/
```

## Customizing UI

The password prompt is styled by default, but you can customize it:

### Custom CSS

Create a CSS file, e.g., `styles/pagevault.css`:

```css
pagevault {
    --bg-color: #f5f5f5;
    --text-color: #333;
    --button-bg: #007bff;
    --button-hover: #0056b3;
}

pagevault-prompt {
    font-family: 'Comic Sans', cursive;  /* Just kidding! */
}
```

Apply when encrypting:

```bash
pagevault lock example.html --css styles/pagevault.css
```

### Custom Titles and Hints

```bash
pagevault mark example.html --title "Premium Content" --hint "Check your email"
pagevault lock example.html
```

## Configuration Options

See [Configuration](configuration.md) for all options:
- `remember`: Whether the browser remembers an unlocked page (none/session/local/ask)
- `auto_prompt`: Whether to show password prompt automatically
- `title`: Label for encrypted sections
- `users`: Multi-user encryption

## Inspecting Encrypted Files

After encrypting files, you can inspect and verify them without decrypting.

### View Metadata

Use `info` to see encryption details without a password:

```bash
pagevault info _locked/example.html
```

This shows the encryption algorithm, number of encrypted regions, ciphertext sizes, viewer information, and other metadata.

### Verify a Password

Use `check` to test whether a password is correct:

```bash
pagevault check _locked/example.html -p "your-password"
# Exit code 0 = correct, 1 = incorrect
```

This performs a fast key verification without decrypting the full content. Useful for scripting and CI/CD pipelines.

## Auditing Your Setup

Run `audit` to check your configuration for common issues:

```bash
pagevault audit
```

The audit checks password strength, salt quality, whether `.pagevault.yaml` is in `.gitignore`, and integrity of managed files. Fix any reported issues to improve your security posture.

## Next Steps

- Explore [CLI Reference](cli-reference.md) for all commands
- Read [Use Cases](use-cases.md) for real-world examples
- Check [Configuration](configuration.md) for advanced options
- See [FAQ](faq.md) if you have questions

## Troubleshooting

**Q: Where does pagevault output files?**
A: By default, `_locked/` for encrypted HTML and `_unlocked/` for decrypted. Use `-d` to specify.

**Q: Why doesn't my selector work?**
A: Make sure the CSS selector is valid and matches elements in your HTML. Test with your browser's DevTools.

**Q: Can I encrypt an already-encrypted file?**
A: Yes! pagevault supports composable encryption. Decrypting then re-encrypting is also fine.

**Q: How do I share encrypted content?**
A: Upload the encrypted HTML to your static host and share the password separately (email, Discord, docs, etc.).

**Q: Is there a way to distribute different passwords for different sections?**
A: Use multi-user encryption. See [Configuration](configuration.md).

---

Ready to encrypt? Pick your use case and try it out!
