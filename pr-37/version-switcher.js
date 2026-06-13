(() => {
  const BASE = "/dotsec-rs";

  // Parse "v1.2.3" -> [1, 2, 3]; returns null on malformed.
  function parseVersion(s) {
    const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(s || "");
    return m ? [+m[1], +m[2], +m[3]] : null;
  }

  // Pick the highest semver from each major track. Input: stable list ordered
  // newest-first; output: same shape, one entry per major.
  function latestPerMajor(stable) {
    const seen = new Set();
    const out = [];
    for (const s of stable) {
      const v = parseVersion(s.version);
      if (!v) continue;
      if (seen.has(v[0])) continue;
      seen.add(v[0]);
      out.push(s);
    }
    return out;
  }

  function injectPill(latest) {
    if (!latest) return;
    // Top-right pill — visible on every page; click jumps to the latest stable docs.
    const pill = document.createElement("a");
    pill.className = "version-pill";
    pill.href = `${BASE}${latest.path}`;
    pill.textContent = `Latest stable: ${latest.version}`;
    pill.title = "Jump to the latest stable docs";
    document.body.appendChild(pill);
  }

  async function init() {
    try {
      const res = await fetch(`${BASE}/versions.json`);
      if (!res.ok) return;
      const versions = await res.json();

      const banner = document.createElement("div");
      banner.className = "version-banner";

      const links = [];

      // Stable releases — show latest per major only (eg v6.0.0, v5.0.2)
      // so the banner doesn't grow unboundedly across patches.
      if (versions.stable?.length) {
        const perMajor = latestPerMajor(versions.stable);
        links.push(`<span class="label">Stable:</span>`);
        links.push(
          perMajor
            .map((s) => `<a href="${BASE}${s.path}">${s.version}</a>`)
            .join('<span class="separator">·</span>')
        );

        // Prominent pill in the top-right corner pointing at the very latest.
        injectPill(perMajor[0]);
      }

      // Beta
      if (versions.beta) {
        links.push(
          `<span class="separator">|</span><span class="label">Beta:</span><a href="${BASE}${versions.beta.path}">${versions.beta.label}</a>`
        );
      }

      // PRs
      if (versions.prs?.length) {
        links.push(
          `<span class="separator">|</span><span class="label">PRs:</span>`
        );
        links.push(
          versions.prs
            .map((p) => `<a href="${BASE}${p.path}">${p.label}</a>`)
            .join('<span class="separator">·</span>')
        );
      }

      banner.innerHTML = links.join(" ");
      document.body.appendChild(banner);
    } catch {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
