# Configuration

pagevault uses a cascade of configuration sources:

1. **Command-line flags** (highest priority)
2. **Environment variables** (`PAGEVAULT_PASSWORD`, `PAGEVAULT_CONFIG`)
3. **`.pagevault.yaml` file** in current directory or parent
4. **Defaults** (lowest priority)

## Configuration File

Create `.pagevault.yaml` in your project root:

```bash
pagevault config init
```

### File Format

```yaml
# Encryption settings (required)
password: "your-strong-passphrase"
salt: "auto-generated-32-hex-chars"

# Content padding (prevents size leakage)
pad: false

# Default UI behavior
defaults:
  remember: "ask"        # "none", "session", "local", "ask"
  remember_days: 0       # Days until stored password expires (0 = no expiration)
  auto_prompt: true      # Show password prompt on page load

# Password prompt UI customization
template:
  title: "Protected Content"
  button_text: "Unlock"
  error_text: "Incorrect password"
  hint: "Contact admin for password"

# Multi-user encryption
users:
  alice: "alice-password"
  bob: "bob-password"

# Single default user
user: "alice"

# Viewer plugin overrides (absent = all enabled)
viewers:
  image: true
  pdf: true
  markdown: false

# Managed file globs (for sync command)
managed:
  - "_locked/**/*.html"
```

### Detailed Options

#### `password` (required)

Encryption passphrase. Must be strong. Generated on `config init`.

```yaml
password: "use-a-strong-passphrase-here"
```

#### `salt`

32-character hex string for key derivation. Generated on `config init`. **Do not change unless you intend to re-encrypt all files.**

```yaml
salt: "0123456789abcdef0123456789abcdef"
```

#### `defaults.remember`

How long to remember the password in the browser:

- `"none"`: Don't remember (always prompt)
- `"session"`: Remember for current browser session only
- `"local"`: Remember permanently (localStorage)
- `"ask"`: Ask user each time (default)

```yaml
defaults:
  remember: "session"
```

#### `defaults.remember_days`

For `remember: "local"`, how many days to store the password. `0` = indefinite.

```yaml
defaults:
  remember_days: 30  # Forget after 30 days
```

#### `defaults.auto_prompt`

Show password prompt automatically when page loads (`true`) or only when encrypted content is accessed (`false`).

```yaml
defaults:
  auto_prompt: true
```

#### `template.title`

Label shown in password prompt.

```yaml
template:
  title: "Premium Content"
```

#### `template.button_text`

Text for the "unlock" button.

```yaml
template:
  button_text: "Decrypt"
```

#### `template.error_text`

Error message for wrong password.

```yaml
template:
  error_text: "Wrong password, try again"
```

#### `template.hint`

Default hint shown in password prompt.

```yaml
template:
  hint: "See README for password"
```

#### `users`

Multi-user encryption. Each user gets their own password.

```yaml
users:
  alice: "alice-strong-password"
  bob: "bob-strong-password"
  charlie: "charlie-strong-password"
```

When encrypting with this config, pagevault creates an encrypted file that *any* of these users can decrypt with their password.

#### `user`

Default user for `unlock` command (auto-lookup password from `users` dict).

```yaml
user: "alice"
# pagevault unlock _locked/file.html
# Automatically uses alice's password
```

#### `pad`

Pad content to a power-of-2 boundary before encryption. This prevents attackers from inferring content size from ciphertext length.

```yaml
pad: true
```

Default is `false`. Can also be enabled per-command with the `--pad` flag on `lock`.

#### `viewers`

Enable or disable specific viewer plugins for wrapped file rendering. If this section is absent, all discovered viewers are enabled.

```yaml
viewers:
  image: true      # Enable image viewer (default)
  pdf: true        # Enable PDF viewer (default)
  html: true       # Enable HTML viewer (default)
  text: true       # Enable text viewer (default)
  markdown: false  # Disable Markdown viewer
```

Viewer names correspond to the plugin names registered via entry points. Only viewers that are both installed and enabled will be embedded in locked output.

#### `viewers_dir` and `css_file`

`viewers_dir` names a directory of custom viewer `.py` files, which pagevault imports and runs. `css_file` names a stylesheet whose contents are embedded in locked output. Relative paths resolve against the config file's directory.

Because these keys load code or files, they are honored only from a *trusted* config: one passed with `-c`, or one whose directory contains your working directory (you are running pagevault from inside that project). A config found only by searching upward from an input path elsewhere, for example `pagevault lock ~/Downloads/cloned/doc.txt`, still supplies passwords and settings, but if it sets either key pagevault stops with an error instead of running that project's code. Pass `-c path/to/.pagevault.yaml` to trust it explicitly.

#### `managed`

File patterns for `sync` command. Useful for automated re-encryption workflows.

```yaml
managed:
  - "_locked/**/*.html"
  - "public/protected/**/*.html"
```

## Environment Variables

Override configuration file settings:

```bash
# Set password via environment
export PAGEVAULT_PASSWORD="temporary-password"
pagevault lock page.html

# Specify config file location
export PAGEVAULT_CONFIG="/path/to/custom.yaml"
pagevault lock page.html
```

## Command-Line Flags

Highest priority; override all configuration files and environment variables.

```bash
pagevault lock page.html -p "command-line-password"
pagevault lock page.html -u alice  # Use alice's multi-user password
pagevault lock page.html -d _encrypted/  # Custom output directory
```

See [CLI Reference](cli-reference.md) for all flags.

## Configuration Cascade Example

Given this file: `.pagevault.yaml`

```yaml
password: "config-password"
defaults:
  remember: "local"
  auto_prompt: true
```

And environment variable: `PAGEVAULT_PASSWORD="env-password"`

And command-line flag: `-p "cli-password"`

**Result:**
- Password used: `"cli-password"` (command-line wins)
- Remember mode: `"local"` (from config)
- Auto-prompt: `true` (from config)

## .gitignore

**Always add `.pagevault.yaml` to `.gitignore`!**

```
.pagevault.yaml
```

Your configuration contains passwords. Don't commit them to version control.

## Finding Your Config File

```bash
pagevault config where
# Output: /path/to/current/project/.pagevault.yaml
```

## Security Best Practices

1. **Use strong passwords**: At least 16 characters, mix of types
2. **Don't commit config**: Add to `.gitignore`
3. **Use password manager**: Store passwords in KeePass, 1Password, etc.
4. **Rotate passwords**: Use `pagevault config user passwd` to update users
5. **Use environment variables in CI/CD**: Don't embed passwords in scripts

Example CI/CD setup:

```bash
# GitHub Actions
pagevault lock page.html -p "${{ secrets.PAGEVAULT_PASSWORD }}"
```

```bash
# GitLab CI
pagevault lock page.html -p "$PAGEVAULT_PASSWORD"
```

## Examples

### Single-User Static Site

```yaml
password: "super-secret-passphrase"
salt: "abc123def456abc123def456abc123de"

defaults:
  remember: "session"
  auto_prompt: true

template:
  title: "Protected Content"
  hint: "Check your email for password"
```

### Multi-User Knowledge Base

```yaml
users:
  team: "team-password"
  external: "external-password"

user: "team"

defaults:
  remember: "local"
  remember_days: 365

template:
  title: "Documentation"
  hint: "Internal: team password. External: external password"
```

### Hugo Blog with Custom Styling

```yaml
password: "blog-password"

defaults:
  remember: "ask"

template:
  title: "Premium Article"
  button_text: "Read Full Article"
  error_text: "Incorrect password"
  hint: "Support pagevault on GitHub to get the password"
```

## Troubleshooting

**Q: Why is my config file not being found?**
A: pagevault searches up the directory tree. Make sure `.pagevault.yaml` is in your project root or specify `-c /path/to/config.yaml`.

**Q: Can I use different passwords for different files?**
A: Use command-line flag: `pagevault lock -p "password1" file1.html && pagevault lock -p "password2" file2.html`

**Q: How do I change the password?**
A: Edit `.pagevault.yaml` password field, then re-encrypt: `pagevault lock _locked/ -r`

**Q: Can I rotate multi-user passwords?**
A: Yes! Use `pagevault config user passwd alice` to update alice's password, then sync: `pagevault sync _locked/ -r`

---

[← Back to Getting Started](getting-started.md)
