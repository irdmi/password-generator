# 🔐 Secure Password Generator

## English README

### 🖥 Standard Mode (No `#`)
Open the page normally to use the interactive interface. Select password length, toggle character sets (lowercase, uppercase, digits, symbols, safe mode), switch between light/dark themes, generate, and copy with one click. Ideal for everyday manual use.

### 🔗 URL Hash Mode (With `#`)
Add parameters directly to the URL to bypass the UI and get instant output. Designed for bookmarks, scripts, automation, or embedding. Returns either plain text or structured JSON.

### ⚙️ How to Configure the Hash
Format: `#<length>-<sets>[,<mode>]`
- **Sets:** `az` (lowercase), `AZ` (uppercase), `09` (digits), `sym` (symbols), `safe` (exclude `i/l/1/O/0`)
- **Modes:** `json` (returns metadata), `plain` (returns only the password string)
- **Examples:**
  - `#16-az,AZ,09,sym` → UI with a standard password
  - `#32-az,09,json` → JSON output
  - `#64-az,AZ,09,sym,safe,plain` → Plain text, safe characters only

### 🛡️ Why It's Secure & Private
- ✅ **100% Client-Side:** Generation happens entirely in your browser. Zero network requests, zero analytics, zero tracking.
- ✅ **Cryptographically Strong:** Uses `crypto.getRandomValues()` with rejection sampling to eliminate modulo bias.
- ✅ **Zero Persistence:** Passwords are never stored, cached, or transmitted. Clearing the tab erases everything.
- ✅ **Offline-Ready:** Works without an internet connection. Open-source.
