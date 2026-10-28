(function () {
  "use strict";

  /* ---------- SOC Triage Simulator ---------- */
  const ALERTS = [
    {
      title: "Successful login after brute force",
      desc: "User jane.doe@company.com had 47 failed login attempts from 203.0.113.45, then one successful login from the same IP.",
      logs: "2026-10-28 09:12:01 auth-fail user=jane.doe src=203.0.113.45\n" +
            "2026-10-28 09:12:03 auth-fail user=jane.doe src=203.0.113.45\n" +
            "... (45 more failures) ...\n" +
            "2026-10-28 09:14:22 auth-success user=jane.doe src=203.0.113.45 mfa=none",
      action: "escalate",
      reason: "Pattern matches password spraying / brute-force followed by account compromise. Escalate for containment and forced password reset."
    },
    {
      title: "Scheduled backup completed",
      desc: "The nightly database backup job ran successfully from the backup service account.",
      logs: "2026-10-28 02:00:00 backup-job db-backup status=success duration=14m account=svc-backup",
      action: "dismiss",
      reason: "Expected scheduled maintenance. No security relevance."
    },
    {
      title: "Office app spawned PowerShell",
      desc: "User opened invoice.docm from an external email; winword.exe immediately started powershell.exe.",
      logs: "2026-10-28 11:34:12 process-create parent=winword.exe child=powershell.exe user=bob cmd='powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUA...'",
      action: "escalate",
      reason: "Office document spawning encoded PowerShell is a classic malware delivery chain. Escalate immediately for host isolation."
    },
    {
      title: "Inbound port scan blocked",
      desc: "Firewall blocked ~2,000 SYN packets from 198.51.100.22 across SSH, RDP, and SMB ports.",
      logs: "2026-10-28 13:10:00 firewall drop src=198.51.100.22 proto=tcp ports=22,3389,445 count=2000 action=blocked",
      action: "dismiss",
      reason: "Attack was blocked at the perimeter. No internal compromise indicated — log for trending, but no escalation needed."
    },
    {
      title: "DNS queries to DGA domains",
      desc: "Endpoint DESKTOP-42 made 50 DNS queries to random-looking .xyz domains in two minutes.",
      logs: "2026-10-28 15:22:10 dns-query host=DESKTOP-42 name=qxk7f2b.xyz\n" +
            "2026-10-28 15:22:11 dns-query host=DESKTOP-42 name=zz9plm4.xyz\n" +
            "...",
      action: "escalate",
      reason: "High-volume queries to algorithmic domains strongly suggest C2 beaconing. Escalate for host isolation and DNS forensics."
    }
  ];

  let triageIndex = 0;
  let triageScore = 0;
  let triageAnswered = false;

  function renderTriage() {
    const a = ALERTS[triageIndex];
    document.getElementById("triageCounter").textContent = "Alert " + (triageIndex + 1) + " / " + ALERTS.length;
    document.getElementById("triageScore").textContent = "Score: " + triageScore;
    document.getElementById("triageTitle").textContent = a.title;
    document.getElementById("triageDesc").textContent = a.desc;
    document.getElementById("triageLogs").textContent = a.logs;
    document.getElementById("triageFeedback").hidden = true;
    document.getElementById("btnNextAlert").hidden = true;
    document.getElementById("btnEscalate").disabled = false;
    document.getElementById("btnDismiss").disabled = false;
    triageAnswered = false;
  }

  function answerTriage(action) {
    if (triageAnswered) return;
    triageAnswered = true;
    const a = ALERTS[triageIndex];
    const correct = action === a.action;
    if (correct) triageScore += 1;
    const fb = document.getElementById("triageFeedback");
    fb.hidden = false;
    fb.className = "feedback " + (correct ? "ok" : "bad");
    fb.textContent = (correct ? "Correct. " : "Not quite. ") + a.reason;
    document.getElementById("btnEscalate").disabled = true;
    document.getElementById("btnDismiss").disabled = true;
    document.getElementById("triageScore").textContent = "Score: " + triageScore;

    const next = document.getElementById("btnNextAlert");
    if (triageIndex + 1 < ALERTS.length) {
      next.hidden = false;
      next.textContent = "Next alert";
      next.onclick = function () { triageIndex += 1; renderTriage(); };
    } else {
      next.hidden = false;
      next.textContent = "Finish";
      next.onclick = function () {
        fb.textContent = "Simulation complete. Final score: " + triageScore + " / " + ALERTS.length + ". " +
          (triageScore === ALERTS.length ? "Solid L1 instincts." : "Review the missed cases and try again.");
        next.hidden = true;
      };
    }
  }

  document.getElementById("btnEscalate").addEventListener("click", function () { answerTriage("escalate"); });
  document.getElementById("btnDismiss").addEventListener("click", function () { answerTriage("dismiss"); });
  renderTriage();

  /* ---------- Email Header Analyzer ---------- */
  function extractHeaders(raw) {
    const headers = {};
    const lines = raw.replace(/\r\n/g, "\n").split("\n");
    let key = null;
    lines.forEach(function (line) {
      if (line.trim() === "") return;
      const cont = line.match(/^\s+/);
      if (cont && key) {
        headers[key] += " " + line.trim();
      } else {
        const m = line.match(/^([^:]+):\s*(.*)$/);
        if (m) {
          key = m[1].trim().toLowerCase();
          headers[key] = m[2].trim();
        }
      }
    });
    return headers;
  }

  function parseReceived(raw) {
    const all = [];
    const lines = raw.replace(/\r\n/g, "\n").split("\n");
    let buffer = "";
    lines.forEach(function (line) {
      if (line.toLowerCase().startsWith("received:")) {
        if (buffer) all.push(buffer.trim());
        buffer = line.substring(9).trim();
      } else if (/^\s/.test(line) && buffer) {
        buffer += " " + line.trim();
      } else {
        if (buffer) { all.push(buffer.trim()); buffer = ""; }
      }
    });
    if (buffer) all.push(buffer.trim());
    return all.reverse();
  }

  function extractDomain(addr) {
    const m = addr.match(/@([a-zA-Z0-9.-]+)/);
    return m ? m[1].toLowerCase() : "";
  }

  function analyzeHeaders() {
    const raw = document.getElementById("headerInput").value;
    const headers = extractHeaders(raw);
    const received = parseReceived(raw);
    const auth = headers["authentication-results"] || "";
    const from = headers["from"] || "";
    const returnPath = headers["return-path"] || "";
    const replyTo = headers["reply-to"] || "";
    const fromDomain = extractDomain(from);
    const rpDomain = extractDomain(returnPath);
    const rtDomain = extractDomain(replyTo);

    const findings = [];
    if (fromDomain && rpDomain && fromDomain !== rpDomain) {
      findings.push("Return-Path domain (" + rpDomain + ") does not match From domain (" + fromDomain + ").");
    }
    if (fromDomain && rtDomain && fromDomain !== rtDomain) {
      findings.push("Reply-To domain (" + rtDomain + ") differs from From domain — possible redirect.");
    }
    if (/spf=fail/.test(auth)) findings.push("SPF check failed.");
    if (/dkim=fail/.test(auth)) findings.push("DKIM signature failed.");
    if (/dmarc=fail/.test(auth)) findings.push("DMARC policy failed.");
    if (!auth.includes("spf=") && !auth.includes("dkim=") && !auth.includes("dmarc=")) {
      findings.push("No SPF/DKIM/DMARC authentication results found — cannot verify sender.");
    }
    const suspicious = /amaz0n|micr0soft|paypa1|app1e|faceb00k|secure-update|account-verify/.test(fromDomain + " " + rpDomain);
    if (suspicious) findings.push("Sender domain looks like a brand lookalike / typosquat.");

    const summary = document.getElementById("headerSummary");
    summary.innerHTML = [
      "<div><strong>From:</strong> " + (from || "—") + "</div>",
      "<div><strong>To:</strong> " + (headers["to"] || "—") + "</div>",
      "<div><strong>Subject:</strong> " + (headers["subject"] || "—") + "</div>",
      "<div><strong>Date:</strong> " + (headers["date"] || "—") + "</div>",
      "<div><strong>Return-Path:</strong> " + (returnPath || "—") + "</div>",
      "<div><strong>Authentication-Results:</strong> " + (auth || "—") + "</div>"
    ].join("");

    const chain = document.getElementById("headerReceived");
    chain.innerHTML = received.length ? received.map(function (h) { return "<li>" + h + "</li>"; }).join("") : "<li>No Received headers found.</li>";

    const list = document.getElementById("headerFindings");
    if (findings.length === 0) {
      list.innerHTML = "<li class=\"ok\">No obvious spoofing signs detected, but always verify requests manually.</li>";
    } else {
      list.innerHTML = findings.map(function (f) { return "<li>" + f + "</li>"; }).join("");
    }

    document.getElementById("headerOutput").hidden = false;
  }

  document.getElementById("btnAnalyzeHeaders").addEventListener("click", analyzeHeaders);

  /* ---------- IOC Lookup Trainer ---------- */
  const IOC_DB = {
    ip: {
      "203.0.113.45": { verdict: "malicious", reason: "Brute-force source seen in recent phishing campaign.", action: "Block at firewall and check any successful logins from this IP." },
      "198.51.100.22": { verdict: "malicious", reason: "Known internet-wide scanner / noise node.", action: "No internal action if blocked; add to watchlist." },
      "192.0.2.10": { verdict: "benign", reason: "Internal company egress proxy.", action: "No action required." }
    },
    domain: {
      "amaz0n-security.com": { verdict: "malicious", reason: "Amazon lookalike used in credential phishing.", action: "Block domain and search mail logs for deliveries." },
      "evil-c2.xyz": { verdict: "malicious", reason: "DGA domain associated with malware C2.", action: "Block DNS and isolate querying endpoints." },
      "github.com": { verdict: "benign", reason: "Known legitimate service.", action: "No action required." }
    },
    hash: {
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": { verdict: "malicious", reason: "EICAR test file (harmless, but matches malware-detection signatures).", action: "If not an intentional test, investigate how it arrived." },
      "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2": { verdict: "unknown", reason: "No intelligence on this hash.", action: "Submit to sandbox / VirusTotal and monitor for detonations." }
    },
    url: {
      "http://amaz0n-secure-login.tk/verify": { verdict: "malicious", reason: "Phishing landing page impersonating Amazon.", action: "Block URL and domain; report to takedown." },
      "https://www.google.com": { verdict: "benign", reason: "Known legitimate service.", action: "No action required." }
    }
  };

  function lookupIoc() {
    const type = document.getElementById("iocType").value;
    const value = document.getElementById("iocValue").value.trim().toLowerCase();
    const out = document.getElementById("iocOutput");
    out.hidden = false;

    let rec = IOC_DB[type] && IOC_DB[type][value];
    if (!rec) {
      // random-ish but stable verdict for unknowns
      const hash = value.split("").reduce(function (a, c) { return ((a << 5) - a) + c.charCodeAt(0) | 0; }, 0);
      const verdicts = ["benign", "benign", "unknown", "unknown", "malicious"];
      const v = verdicts[Math.abs(hash) % verdicts.length];
      rec = {
        verdict: v,
        reason: "No direct intelligence match. Simulated verdict for training.",
        action: v === "malicious" ? "Treat as suspicious: block and investigate." : (v === "benign" ? "No action required." : "No action without additional context; enrich and monitor.")
      };
    }

    const vEl = document.getElementById("iocVerdict");
    vEl.textContent = rec.verdict.toUpperCase();
    vEl.className = "verdict " + rec.verdict;
    document.getElementById("iocDetails").innerHTML = "<p><strong>Reason:</strong> " + rec.reason + "</p>";
    document.getElementById("iocAction").innerHTML = "<strong>Recommended action:</strong> " + rec.action;
  }

  document.getElementById("btnIocLookup").addEventListener("click", lookupIoc);

  /* ---------- MITRE ATT&CK Mapper ---------- */
  const TECHNIQUES = [
    { id: "T1566.001", name: "Spearphishing Attachment" },
    { id: "T1566.002", name: "Spearphishing Link" },
    { id: "T1078", name: "Valid Accounts" },
    { id: "T1110", name: "Brute Force" },
    { id: "T1059.001", name: "PowerShell" },
    { id: "T1071", name: "Application Layer Protocol" },
    { id: "T1567", name: "Exfiltration Over Web Service" },
    { id: "T1057", name: "Process Discovery" }
  ];

  const MITRE_SCENARIOS = [
    {
      text: "User opened invoice.docm from an external email; winword.exe immediately started powershell.exe with an encoded command.",
      answer: "T1059.001",
      explanation: "Office macro/document launching PowerShell is Execution: Command and Scripting Interpreter: PowerShell."
    },
    {
      text: "Attacker obtained an employee's password and logged in after dozens of failed attempts from a single IP.",
      answer: "T1110",
      explanation: "Repeated failed authentication attempts followed by success map to Credential Access: Brute Force."
    },
    {
      text: "Malware on DESKTOP-42 is sending HTTPS beacons to attacker-controlled domains every 60 seconds.",
      answer: "T1071",
      explanation: "C2 over a common application-layer protocol (HTTPS) maps to Command and Control: Application Layer Protocol."
    },
    {
      text: "Phishing email contains a link to a fake Office 365 login page that steals credentials.",
      answer: "T1566.002",
      explanation: "A malicious link in email is Initial Access: Phishing: Spearphishing Link."
    }
  ];

  let mitreIndex = 0;
  let mitreScore = 0;
  let mitreAnswered = false;

  const mitreSelect = document.getElementById("mitreSelect");
  TECHNIQUES.forEach(function (t) {
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = t.id + " — " + t.name;
    mitreSelect.appendChild(opt);
  });

  function renderMitre() {
    const s = MITRE_SCENARIOS[mitreIndex];
    document.getElementById("mitreCounter").textContent = "Scenario " + (mitreIndex + 1) + " / " + MITRE_SCENARIOS.length;
    document.getElementById("mitreScore").textContent = "Score: " + mitreScore;
    document.getElementById("mitreScenario").textContent = s.text;
    mitreSelect.value = "";
    document.getElementById("mitreFeedback").hidden = true;
    document.getElementById("btnMitreNext").hidden = true;
    document.getElementById("btnMitreSubmit").disabled = false;
    mitreAnswered = false;
  }

  function submitMitre() {
    if (mitreAnswered) return;
    mitreAnswered = true;
    const s = MITRE_SCENARIOS[mitreIndex];
    const selected = mitreSelect.value;
    const correct = selected === s.answer;
    if (correct) mitreScore += 1;
    const fb = document.getElementById("mitreFeedback");
    fb.hidden = false;
    fb.textContent = (correct ? "Correct. " : "Not quite. ") + s.explanation;
    document.getElementById("btnMitreSubmit").disabled = true;
    document.getElementById("mitreScore").textContent = "Score: " + mitreScore;

    const next = document.getElementById("btnMitreNext");
    if (mitreIndex + 1 < MITRE_SCENARIOS.length) {
      next.hidden = false;
      next.textContent = "Next scenario";
      next.onclick = function () { mitreIndex += 1; renderMitre(); };
    } else {
      next.hidden = false;
      next.textContent = "Finish";
      next.onclick = function () {
        fb.textContent = "Done. Final score: " + mitreScore + " / " + MITRE_SCENARIOS.length + ". " +
          (mitreScore === MITRE_SCENARIOS.length ? "Great technique mapping." : "Review the missed techniques.");
        next.hidden = true;
      };
    }
  }

  document.getElementById("btnMitreSubmit").addEventListener("click", submitMitre);
  renderMitre();
})();
