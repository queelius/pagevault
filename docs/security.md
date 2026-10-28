# Security

pagevault uses industry-standard cryptography and best practices to protect encrypted content.

## Cryptography

### Encryption Algorithm

**AES-256-GCM** (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)

- **Standard:** NIST approved, used by TLS, Signal, and other production systems
- **Key size:** 256 bits (2^256 possible keys)
- **Mode:** GCM provides authenticated encryption (detects tampering)
- **Implementation:** WebCrypto API (built into all modern browsers)

### Key Derivation

**PBKDF2-SHA256** with 310,000 iterations

- **Standard:** OWASP recommended as of 2023
- **Hash function:** SHA-256 (cryptographically secure)
- **Iterations:** 310,000 (computationally expensive, slows down brute-force attacks)
- **Salt:** 32-character random hex, unique per configuration

### Authentication

GCM mode includes authentication. If encrypted content is tampered with, decryption fails and error message shows.

## Security Properties

### ✅ What pagevault Protects

1. **Content confidentiality**: Encrypted content is unreadable without password
2. **Tamper detection**: Modified encrypted files won't decrypt
3. **Password-based access**: Same password required by each user
4. **No plaintext leakage**: Encrypted files contain only ciphertext and metadata

### ❌ What pagevault Does NOT Protect

1. **Password security**: We use standard algorithms. Your password strength matters.
2. **Distribution security**: If you share password insecurely, attacker can decrypt
3. **Browser security**: If visitor's computer is compromised, password can be stolen
4. **Source control**: Don't commit `.pagevault.yaml` to version control
5. **Server security**: If your hosting is compromised, files can be accessed

pagevault is **client-side only**. It can't protect against attacks on your server, distribution channel, or visitor's machine.

## Threat Model

pagevault is designed to protect against **opportunistic attackers**:

- ✅ Casual browser: Can't view encrypted content without password
- ✅ Automated scanners: Can't extract plaintext from encrypted HTML
- ✅ Archive crawlers: Can't index encrypted sections
- ✅ Data breaches: Encrypted files are useless without password

pagevault is **NOT** designed for:

- ❌ Government-level adversaries with extensive resources
- ❌ Attackers with physical access to visitor's computer
- ❌ Compromised hosting infrastructure
- ❌ Weak passwords (pagevault can't fix password selection)

## Practical Security Advice

### Passwords

1. **Use strong passwords**
   - At least 16 characters
   - Mix uppercase, lowercase, numbers, symbols
   - Use a password manager (KeePass, 1Password, Bitwarden)
   - Avoid dictionary words, personal info, patterns

   ```bash
   # Bad: "password123", "Site2024", "MyBlog"
   # Good: "7#kL9$pQ2mX!vN4bW" (from password manager)
   ```

2. **Rotate passwords periodically**
   ```bash
   pagevault config user passwd alice
   pagevault sync _locked/ -r  # Re-encrypt with new password
   ```

3. **Don't reuse passwords**
   - Use different password for pagevault than your email, GitHub, etc.
   - If one service is compromised, others aren't affected

### Configuration Files

1. **Add `.pagevault.yaml` to `.gitignore`**
   ```bash
   echo ".pagevault.yaml" >> .gitignore
   git rm --cached .pagevault.yaml  # If already committed
   ```

2. **Store backups securely**
   - Password manager
   - Encrypted external drive
   - KMS system (AWS Secrets Manager, GitHub Secrets, etc.)

3. **Never commit to version control**
   ```bash
   # Bad
   git add .pagevault.yaml
   git commit -m "Add password"

   # Good
   # .pagevault.yaml is in .gitignore
   ```

### Distribution

1. **Separate password from HTML**
   ```bash
   # ✅ Good: File and password distributed separately
   # Send HTML file via email attachment
   # Send password via Slack or Signal

   # ❌ Bad: Both in same message
   # Sends: "Password is 'secret' here's the HTML..."
   ```

2. **Use HTTPS for downloads**
   - GitHub Pages: HTTPS enabled by default ✅
   - Netlify: HTTPS enabled by default ✅
   - Self-hosted: Use Let's Encrypt for free HTTPS

3. **Consider temporary passwords for time-limited access**
   ```bash
   # Change password after disclosure period
   pagevault config init  # Generates new password
   pagevault lock site/ -r  # Re-encrypt
   ```

### For Multi-User Setup

1. **Each user gets unique password**
   ```yaml
   users:
     alice: "alice-unique-password"
     bob: "bob-unique-password"
   ```

2. **Rotate individual user passwords**
   ```bash
   pagevault config user passwd alice
   pagevault sync _locked/ -r
   ```

3. **Remove inactive users**
   ```bash
   pagevault config user rm bob
   pagevault sync _locked/ -r
   ```

### For CI/CD Environments

1. **Use secret management**
   ```bash
   # GitHub Actions
   - run: pagevault lock . -p "${{ secrets.PAGEVAULT_PASSWORD }}"

   # GitLab CI
   - pagevault lock . -p "$PAGEVAULT_PASSWORD"

   # Environment variable in CI/CD settings, never in code
   ```

2. **Rotate secrets**
   - Update in GitHub Secrets / GitLab CI Variables
   - Re-run pipeline to re-encrypt

3. **Audit access logs**
   - Who downloaded secrets?
   - When were they accessed?
   - GitHub: Settings → Security → Audit log

## Cryptographic Assumptions

pagevault assumes:

1. **Passwords have sufficient entropy**: Passwords should have ~128+ bits of entropy (use password manager)
2. **WebCrypto implementation is secure**: Browser's native crypto is trusted (tested regularly by browser vendors)
3. **User's computer is trustworthy**: No keylogger, malware, or compromise on visitor's machine
4. **HTTP transmission is secure**: Only access over HTTPS (GitHub Pages, Netlify, etc.)
5. **JavaScript environment is safe**: No malicious scripts injected before pagevault loads

If any assumption is violated, security may be compromised.

## Audit and Transparency

pagevault source code is open. You can:

1. **Review cryptography implementation**
   - See `src/pagevault/crypto.py` for key derivation
   - See `src/pagevault/template.py` for browser-side decryption

2. **Run security tests**
   ```bash
   pytest tests/test_crypto.py -v  # Cryptography tests
   pytest tests/test_integration.py -v  # Full encryption/decryption roundtrips
   ```

3. **Verify WebCrypto compatibility**
   - Check `templates/pagevault.js` for browser-side implementation
   - Uses `SubtleCrypto.decrypt()` with AES-256-GCM

## Viewer Plugin Security

pagevault includes a viewer plugin system for rendering wrapped files (images, PDFs, HTML, text, Markdown) in the browser after decryption. The security model for plugins follows standard Python packaging conventions:

**Trust model: `pip install` = trust.** If you install a third-party package that registers viewer plugins via the `pagevault.viewers` entry point group, that plugin's JavaScript and CSS will be embedded into your encrypted HTML output. This is the same trust model as any Python package -- installing a package grants it the ability to run code in your environment.

**Defense-in-depth measures:**
- Plugin names and MIME types are validated via regex at class definition time (`__init_subclass__`) and again at the injection point
- Plugin JavaScript, CSS, and dependency strings are escaped to prevent `</script>` and `</style>` breakout attacks
- The built-in HTML viewer uses an iframe with `sandbox="allow-same-origin"` (no `allow-scripts`) for display-only rendering
- Plugin names are deduplicated by priority, with warnings logged on collision

**Recommendation:** Only install viewer plugins from packages you trust. Review third-party plugin source code before installing. The built-in viewers (image, PDF, HTML, text, Markdown) are maintained as part of the pagevault project and undergo the same review process as the core code.

## Remembered Passwords

When a visitor ticks "Remember on this device" (or the page uses
`remember: "local"` / `"session"`), the browser keeps the key the password
derives (PBKDF2 over the password and the envelope's salt), never the
password:

- `local`: an IndexedDB entry holding a **non-extractable** `CryptoKey`.
  Scripts on the page's origin can use it to open pagevault pages, but can't
  read its bytes, so it can't be copied off the device. It expires after
  `remember_days` (0 = never).
- `session`: `sessionStorage` holds only strings, so it keeps the key's
  bytes, until the tab closes.

Either way the key opens only pages locked with that password and that salt;
a password reused elsewhere is not exposed. Anyone with access to the browser
profile can still open those pages while the key lasts, which is what
remembering means. `#pagevault_logout` forgets every key for the site.

pagevault 0.4.2 and earlier stored the plaintext password in `localStorage`
or `sessionStorage`; newer pages delete that entry when they load.

## Config File Permissions

`.pagevault.yaml` and the global config hold passwords. pagevault writes them
mode 600 (owner only) and creates the global config directory mode 700;
`pagevault audit` reports a config file other users can read.

## Content Padding

The `--pad` flag (or `pad: true` in config) pads content to the next power-of-2 boundary before encryption. This prevents attackers from inferring content size from ciphertext length, which can be a concern when:

- Encrypted files are publicly hosted and different content lengths could reveal which document is which
- An attacker can observe ciphertext sizes over time and correlate them with known documents

Padding adds space overhead but provides stronger confidentiality guarantees. Consider enabling it for high-sensitivity deployments.

## Known Limitations

1. **Side-channel attacks**: Password might be leaked via timing analysis, power consumption, etc. (not practical for browsers)
2. **Rainbow tables**: If attacker has dictionary of common passwords, they can precompute hashes. Use strong passwords to mitigate.
3. **Brute force**: 310k iterations slows attackers but doesn't eliminate risk if password is weak
4. **Browser bugs**: Potential vulnerabilities in browser's WebCrypto. Keep browser updated.

## Reporting Security Issues

If you discover a vulnerability:

1. **Do not** open a public GitHub issue
2. **Email** security concerns to the maintainer privately
3. **Allow time** for patches before public disclosure

pagevault takes security seriously and will respond quickly to legitimate concerns.

## References

- [NIST AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) – AES specification
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) – PBKDF2 recommendations
- [NIST SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) – PBKDF2 implementation guide
- [RFC 5116](https://tools.ietf.org/html/rfc5116) – AEAD interface and algorithms
- [MDN WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) – Browser API documentation

## Summary

pagevault uses strong, standard cryptography (AES-256-GCM + PBKDF2-SHA256) suitable for protecting sensitive content on static sites.

**Threats pagevault prevents:**
- Casual attackers reading encrypted HTML
- Automated scrapers indexing content
- Archive crawlers capturing pages
- Passive network monitoring

**Your responsibility:**
- Use strong, unique passwords
- Don't share passwords insecurely
- Keep `.pagevault.yaml` out of version control
- Use HTTPS for all deployments
- Keep your browser and OS updated

For questions or concerns, see [FAQ](faq.md).
