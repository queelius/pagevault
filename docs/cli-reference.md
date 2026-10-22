# CLI Reference

## Overview

pagevault provides a command-line interface for encrypting, decrypting, and managing protected content.

```bash
pagevault [COMMAND] [OPTIONS] [PATHS...]
```

## Commands

### lock

Encrypt marked regions or entire files.

```bash
pagevault lock [OPTIONS] [PATHS]...
```

**Use cases:**
- HTML file: Encrypts `<pagevault>` marked regions
- PDF/image: Wraps entire file in encrypted HTML
- Directory: Processes all files recursively

**Examples:**

```bash
# Encrypt marked HTML
pagevault lock page.html

# Encrypt entire PDF into HTML
pagevault lock document.pdf

# Encrypt all HTML files recursively
pagevault lock site/ -r

# Bundle directory as single encrypted site
pagevault lock mysite/ --site -o mysite.html

# Encrypt only elements matching selector
pagevault lock page.html -s "#secret"

# Specify output directory
pagevault lock site/ -r -d _locked/

# Use custom password
pagevault lock page.html -p "password123"

# Show what would happen without changes
pagevault lock page.html --dry-run
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Process directories recursively |
| `--password` | `-p` | Encryption password (overrides config) |
| `--directory` | `-d` | Output directory for encrypted files (default: `_locked/`) |
| `--output` | `-o` | Output file for non-HTML or `--site` mode |
| `--config` | `-c` | Path to config file (default: `.pagevault.yaml`) |
| `--username` | `-u` | Username for single-user encryption (requires `-p`) |
| `--selector` | `-s` | CSS selector to encrypt (can repeat) |
| `--hint` | | Password hint for prompt |
| `--title` | | Title for encrypted section |
| `--remember` | | Password remember mode: `none`, `session`, `local`, `ask` |
| `--css` | | Custom CSS file for password prompt |
| `--site` | | Bundle directory as encrypted site |
| `--entry` | | Entry point for `--site` mode (default: `index.html`) |
| `--pad` | | Pad content to power-of-2 boundary before encryption (prevents size leakage) |
| `--dry-run` | | Preview without changes |

With `--site`, hidden paths (any file or directory whose name starts with `.`, such as `.pagevault.yaml`, `.git/` and `.env`) are never bundled, nor is the output file itself if it lies inside the directory. Everyone who can unlock the site can read every bundled file.

---

### unlock

Decrypt encrypted HTML files (restores `<pagevault>` marked state).

```bash
pagevault unlock [OPTIONS] [PATHS]...
```

**Examples:**

```bash
# Decrypt single file
pagevault unlock _locked/page.html

# Decrypt directory recursively
pagevault unlock _locked/ -r

# Specify output directory
pagevault unlock _locked/ -r -d _restored/

# For multi-user encrypted files
pagevault unlock _locked/page.html -u alice

# Use custom password
pagevault unlock _locked/page.html -p "mypassword"

# Output to stdout for piping
pagevault unlock report.pdf.html --stdout -p "$SECRET" > report.pdf
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Process directories recursively |
| `--password` | `-p` | Decryption password |
| `--username` | `-u` | Username for multi-user encrypted content |
| `--directory` | `-d` | Output directory (default: `_unlocked/`) |
| `--stdout` | | Output decrypted content to stdout (for piping) |
| `--config` | `-c` | Path to config file |
| `--dry-run` | | Preview without changes |

---

### mark

Add `<pagevault>` encryption markers to HTML (doesn't encrypt yet).

```bash
pagevault mark [OPTIONS] [PATHS]...
```

Useful for preparing content before encryption.

**Examples:**

```bash
# Wrap entire body in <pagevault>
pagevault mark page.html

# Wrap elements matching selector
pagevault mark page.html -s ".private"

# Multiple selectors
pagevault mark page.html -s ".private" -s "#secret"

# Add hint and title
pagevault mark page.html -s ".private" --hint "Staff only" --title "Team Notes"

# Process directory recursively
pagevault mark site/ -r
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Process directories recursively |
| `--selector` | `-s` | CSS selector to mark (can repeat) |
| `--hint` | | Password hint text |
| `--title` | | Title for encrypted section |
| `--remember` | | Password remember mode |

---

### sync

Re-encrypt files after password changes or user updates.

```bash
pagevault sync [OPTIONS] [PATHS]...
```

Useful for updating encrypted content when users change or passwords are updated.

**Examples:**

```bash
# Re-encrypt after config change
pagevault sync _locked/ -r

# Force complete re-key
pagevault sync _locked/ -r --rekey

# Dry-run to see what would change
pagevault sync _locked/ -r --dry-run
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Process directories recursively |
| `--rekey` | | Force complete re-key operation |
| `--dry-run` | | Preview without changes |

---

### info

Inspect an encrypted HTML file without requiring a password. Shows encryption metadata, viewer info, and runtime details.

```bash
pagevault info [PATH]
```

**Examples:**

```bash
# Inspect an encrypted file
pagevault info encrypted.html

# Inspect a locked file
pagevault info _locked/index.html
```

The output includes:
- Number of encrypted regions
- Encryption version, algorithm, KDF, and iteration count
- Key blob count (number of users)
- Ciphertext size
- Hints, titles, and remember settings
- Embedded viewer information
- Wrap type (file or site) and associated metadata

---

### check

Verify a password against an encrypted file without decrypting content. Performs fast key verification (one PBKDF2 + one AES-GCM unwrap).

```bash
pagevault check [OPTIONS] [PATH]
```

Exit code 0 means the password is correct; exit code 1 means incorrect.

**Examples:**

```bash
# Verify a password
pagevault check encrypted.html -p "test-password"

# Verify for a specific user
pagevault check _locked/file.html -p "pw" -u alice

# Use in scripts
if pagevault check file.html -p "$PASSWORD"; then
  echo "Password correct"
fi
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--password` | `-p` | Password to verify (required) |
| `--username` | `-u` | Username for multi-user content |

---

### audit

Run comprehensive health checks on configuration and encrypted files. Checks password strength, salt quality, config hygiene, and file integrity.

```bash
pagevault audit [OPTIONS]
```

Exit code 0 means all checks passed (possibly with warnings); exit code 1 means issues were found.

**Examples:**

```bash
# Audit current config
pagevault audit

# Audit specific config file
pagevault audit -c .pagevault.yaml
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Path to config file |

The audit checks:
- **Password strength**: Length, character classes, entropy estimate
- **Salt quality**: Length and randomness
- **Config hygiene**: Whether `.pagevault.yaml` is in `.gitignore`
- **Environment**: Whether `PAGEVAULT_PASSWORD` is set (security warning)
- **File integrity**: Content hashes on managed files

---

### config

Manage pagevault configuration.

```bash
pagevault config [SUBCOMMAND] [OPTIONS]
```

#### config init

Create a new `.pagevault.yaml` configuration file.

```bash
pagevault config init
```

Generates configuration with a random password and salt.

#### config show

Display current configuration (password masked).

```bash
pagevault config show
```

#### config where

Find the configuration file location.

```bash
pagevault config where
```

#### config user add

Add a user for multi-user encryption.

```bash
pagevault config user add [USERNAME]
```

#### config user remove

Remove a user.

```bash
pagevault config user rm [USERNAME]
```

#### config user list

List all configured users.

```bash
pagevault config user list
```

#### config user passwd

Change a user's password.

```bash
pagevault config user passwd [USERNAME]
```

---

## Common Workflows

### Encrypt a Hugo Blog Post

```bash
# Build your site
hugo -o build/

# Encrypt specific post with hint
pagevault lock build/posts/my-post/index.html \
  --hint "See team wiki for password"

# Deploy encrypted version
cp build/posts/my-post/index.html public/
```

### Prepare Content for Multiple Users

```bash
# Add users to config
pagevault config user add alice
pagevault config user add bob

# Encrypt for multiple users
pagevault lock page.html

# Both alice and bob can decrypt with their passwords
```

### Update Encrypted Content

```bash
# Decrypt to edit
pagevault unlock _locked/page.html

# Edit the decrypted file
vim _unlocked/page.html

# Re-encrypt
pagevault lock _unlocked/page.html

# Deploy new version
cp _locked/page.html public/
```

### Create Shareable Encrypted Site Bundle

```bash
# Bundle entire site directory
pagevault lock mysite/ --site -p "share-password" -o mysite-locked.html

# Share the HTML file + password with others
# They can open mysite-locked.html in browser and explore the entire site
```

---

## Exit Codes

- `0`: Success
- `1`: General error (invalid arguments, file not found, etc.)
- `2`: Configuration error (missing password, invalid config file)

---

## Configuration File

pagevault looks for `.pagevault.yaml` in:
1. Path specified with `-c/--config` flag
2. Current directory
3. Parent directories (searches up)
4. Home directory

See [Configuration](configuration.md) for file format and options.

---

## Environment Variables

- `PAGEVAULT_PASSWORD`: Encryption password (overrides `.pagevault.yaml`)
- `PAGEVAULT_CONFIG`: Path to configuration file

---

## Tips

**Use `--dry-run` to preview:**
```bash
pagevault lock page.html --dry-run
# Shows what would happen without making changes
```

**Chain commands:**
```bash
pagevault mark *.html && pagevault lock *.html
```

**Redirect with output directory:**
```bash
pagevault lock . -r -d _locked/
# Mirrors directory structure in _locked/
```

**Use in scripts:**
```bash
#!/bin/bash
set -e  # Exit on error
pagevault mark content/ -r
pagevault lock content/ -r
rsync -av _locked/ public/
git add public/
```
