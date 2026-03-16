---
pageType: home
hero:
  name: dotsec
  text: .env without .env
  tagline: Stop sharing secrets over Slack. Encrypt your .env, commit it to git, decrypt at runtime. Done.
  actions:
    - theme: brand
      text: Get Started →
      link: /guide/
    - theme: alt
      text: npm install -g dotsec
      link: /guide/
features:
  - icon: 🔐
    title: Encrypted in git
    details: Your .env becomes a .sec file — encrypted with AWS KMS and committed alongside your code. One source of truth, version-controlled.
  - icon: 🧠
    title: Decrypted in memory only
    details: Secrets are never written to disk. Decrypted on the fly when you run your app, then gone.
  - icon: 🚀
    title: Drop-in replacement
    details: Already have a .env? One command to encrypt it. dotsec run injects vars exactly like dotenv — your app doesn't change.
  - icon: 🛡️
    title: Redacted output
    details: Accidentally logging a secret? dotsec intercepts stdout and redacts sensitive values before they hit your terminal or CI logs.
  - icon: 📦
    title: Works everywhere
    details: Available as a CLI via npm and cargo. Native Node.js bindings (@dotsec/core) for parsing and validating .env files programmatically.
  - icon: ✅
    title: Validation built in
    details: Directives like @encrypt, @required, and @format let you enforce rules on your env vars. Catch misconfigurations before they hit production.
---
