/* SecurityOps 101 — beginner cybersecurity lab.
 * All logic runs client-side. No tracking, no external APIs. */

(function () {
  "use strict";

  /* ---------- Tabs ---------- */
  const tabs = document.querySelectorAll(".tab");
  const labs = document.querySelectorAll(".lab");

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      const target = tab.dataset.tab;
      tabs.forEach(function (t) {
        t.classList.toggle("active", t === tab);
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
      });
      labs.forEach(function (lab) {
        lab.classList.toggle("active", lab.id === target);
      });
    });
  });

  /* ---------- Password Lab ---------- */
  const pwdInput = document.getElementById("pwdInput");
  const pwdMeter = document.querySelector(".meter-bar");
  const pwdResult = document.getElementById("pwdResult");
  const pwdTips = document.getElementById("pwdTips");

  function estimateCrackTime(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/\d/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
    if (pool === 0) return null;

    const combinations = Math.pow(pool, password.length);
    const guessesPerSec = 1e10; // offline hash-cracking rig
    const seconds = combinations / guessesPerSec / 2; // average case
    return seconds;
  }

  function formatTime(seconds) {
    if (!isFinite(seconds) || seconds < 1e-6) return "instantly";
    const units = [
      [31536000, "year"],
      [2592000, "month"],
      [86400, "day"],
      [3600, "hour"],
      [60, "minute"],
      [1, "second"]
    ];
    for (const [limit, label] of units) {
      if (seconds >= limit) {
        const val = Math.floor(seconds / limit);
        return `${val} ${label}${val === 1 ? "" : "s"}`;
      }
    }
    return "less than a second";
  }

  function evaluatePassword(pwd) {
    const checks = [
      { label: "At least 8 characters", ok: pwd.length >= 8 },
      { label: "At least 12 characters", ok: pwd.length >= 12 },
      { label: "Lowercase letters", ok: /[a-z]/.test(pwd) },
      { label: "Uppercase letters", ok: /[A-Z]/.test(pwd) },
      { label: "Numbers", ok: /\d/.test(pwd) },
      { label: "Symbols (!@#$ etc.)", ok: /[^a-zA-Z0-9]/.test(pwd) }
    ];

    let score = 0;
    if (pwd.length >= 8) score += 1;
    if (pwd.length >= 12) score += 1;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) score += 1;
    if (/\d/.test(pwd)) score += 1;
    if (/[^a-zA-Z0-9]/.test(pwd)) score += 1;
    if (pwd.length >= 16) score += 1;

    const levels = [
      { min: 0, text: "Very weak — basically public", color: "#ef4444" },
      { min: 2, text: "Weak — crackable in hours", color: "#f87171" },
      { min: 3, text: "Fair — better than nothing", color: "#f59e0b" },
      { min: 4, text: "Good — decent for most accounts", color: "#22c55e" },
      { min: 5, text: "Strong — would take ages to crack", color: "#16a34a" },
      { min: 6, text: "Excellent — overkill, but nice", color: "#15803d" }
    ];
    const level = levels.slice().reverse().find(function (l) { return score >= l.min; }) || levels[0];
    const width = Math.min(100, (score / 6) * 100);

    return { checks, level, width, crackTime: estimateCrackTime(pwd) };
  }

  pwdInput.addEventListener("input", function () {
    const pwd = pwdInput.value;
    if (!pwd) {
      pwdMeter.style.width = "0%";
      pwdResult.textContent = "Start typing…";
      pwdTips.innerHTML = "";
      return;
    }
    const ev = evaluatePassword(pwd);
    pwdMeter.style.width = ev.width + "%";
    pwdMeter.style.background = ev.level.color;
    pwdResult.textContent = ev.level.text + (ev.crackTime ? ` — estimated crack time: ${formatTime(ev.crackTime)}` : "");
    pwdTips.innerHTML = ev.checks.map(function (c) {
      return `<li class="${c.ok ? "ok" : ""}">${c.ok ? "✓" : "○"} ${c.label}</li>`;
    }).join("");
  });

  /* ---------- Phishing Lab ---------- */
  const flagElements = document.querySelectorAll("[data-flag]");
  const foundFlags = new Set();

  flagElements.forEach(function (el) {
    el.addEventListener("click", function () {
      const flag = el.dataset.flag;
      if (foundFlags.has(flag)) {
        foundFlags.delete(flag);
        el.classList.remove("found");
      } else {
        foundFlags.add(flag);
        el.classList.add("found");
      }
    });
  });

  const phishFeedback = document.getElementById("phishFeedback");
  const checkPhishBtn = document.getElementById("checkPhish");

  const flagDescriptions = {
    "spoofed-sender": "The sender domain is 'amaz0n-security.com' — a lookalike, not amazon.com.",
    "urgency": "Urgency ('URGENT', '24 hours') is a classic pressure tactic.",
    "malicious-link": "The link points to 'amaz0n-secure-login.tk', a suspicious domain unrelated to Amazon."
  };

  checkPhishBtn.addEventListener("click", function () {
    const allFlags = Array.from(flagElements).map(function (el) { return el.dataset.flag; });
    const uniqueFlags = [...new Set(allFlags)];
    const missed = uniqueFlags.filter(function (f) { return !foundFlags.has(f); });

    let html = "";
    if (missed.length === 0) {
      html += "🎉 Perfect! You found every red flag.\n\n";
    } else {
      html += `You found ${foundFlags.size} of ${uniqueFlags.length} flags.\n\n`;
      html += "Missed flags:\n";
      missed.forEach(function (f) {
        html += `• ${flagDescriptions[f] || f}\n`;
      });
    }
    html += "\nWhy this email is phishing:\n";
    html += "Real companies rarely threaten account suspension in the subject line, and they never ask you to click random links to 'verify' credentials. When in doubt, open the site manually by typing the address.";

    phishFeedback.textContent = html;
    phishFeedback.style.display = "block";

    // Reveal missed flags visually
    flagElements.forEach(function (el) {
      if (!foundFlags.has(el.dataset.flag)) {
        el.classList.add("missed");
      }
    });
  });

  /* ---------- Permissions Lab ---------- */
  const permsGrid = document.getElementById("permsGrid");
  const permNumeric = document.getElementById("permNumeric");
  const permSymbolic = document.getElementById("permSymbolic");
  const permOutcome = document.getElementById("permOutcome");

  const groups = [
    { key: "owner", label: "Owner (you)" },
    { key: "group", label: "Group" },
    { key: "other", label: "Others" }
  ];
  const bits = [
    { key: "r", label: "Read (4)" },
    { key: "w", label: "Write (2)" },
    { key: "x", label: "Execute (1)" }
  ];

  const state = { owner: { r: true, w: true, x: true }, group: { r: true, w: false, x: true }, other: { r: true, w: false, x: false } };

  function renderPermissions() {
    permsGrid.innerHTML = "";
    groups.forEach(function (g) {
      const card = document.createElement("div");
      card.className = "perm-group";
      const h3 = document.createElement("h3");
      h3.textContent = g.label;
      card.appendChild(h3);

      bits.forEach(function (b) {
        const row = document.createElement("div");
        row.className = "perm-bit";
        const label = document.createElement("span");
        label.textContent = b.label;
        const toggle = document.createElement("input");
        toggle.type = "checkbox";
        toggle.className = "toggle";
        toggle.checked = !!state[g.key][b.key];
        toggle.addEventListener("change", function () {
          state[g.key][b.key] = toggle.checked;
          updatePermissions();
        });
        row.appendChild(label);
        row.appendChild(toggle);
        card.appendChild(row);
      });

      permsGrid.appendChild(card);
    });
    updatePermissions();
  }

  function updatePermissions() {
    let numeric = 0;
    let symbolic = "-";

    groups.forEach(function (g, gi) {
      let n = 0;
      let s = "";
      if (state[g.key].r) { n += 4; s += "r"; } else { s += "-"; }
      if (state[g.key].w) { n += 2; s += "w"; } else { s += "-"; }
      if (state[g.key].x) { n += 1; s += "x"; } else { s += "-"; }
      numeric = numeric * 10 + n;
      symbolic += s;
    });

    permNumeric.textContent = String(numeric).padStart(3, "0");
    permSymbolic.textContent = symbolic;

    const ownerR = state.owner.r;
    const ownerW = state.owner.w;
    const ownerX = state.owner.x;
    const otherR = state.other.r;
    const otherW = state.other.w;

    let outcome = "";
    if (ownerR && ownerW && ownerX) {
      outcome = "As the owner, you can read, edit, and run this file. ";
    } else if (ownerR && ownerW) {
      outcome = "As the owner, you can read and edit this file, but not execute it. ";
    } else if (ownerR) {
      outcome = "As the owner, you can only read this file. ";
    } else {
      outcome = "As the owner, you cannot access this file at all. ";
    }

    if (otherW) {
      outcome += "⚠️ Warning: everyone else on the system can modify this file. That's usually a bad idea.";
    } else if (otherR) {
      outcome += "Everyone else can read it, but not change it.";
    } else {
      outcome += "Others cannot access it.";
    }

    permOutcome.textContent = outcome;
  }

  renderPermissions();
})();
