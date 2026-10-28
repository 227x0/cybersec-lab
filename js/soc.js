(function () {
  "use strict";

  /* ---------- Helpers ---------- */
  function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
  function genIP() {
    return randInt(1, 223) + "." + randInt(0, 255) + "." + randInt(0, 255) + "." + randInt(1, 254);
  }
  function genUser() { return rand(["jane.doe", "john.smith", "alice.wong", "bob.miller", "helpdesk", "admin", "mike.ross", "sara.connor"]); }
  function genHost() { return rand(["DESKTOP-42", "LAPTOP-07", "SRV-WEB-01", "SRV-DB-02", "WKSTN-118", "MAIL-01", "DESKTOP-99"]); }
  function genDomain() { return rand(["evil-c2.xyz", "phish-login.tk", "malware-drop.ru", "badsite.kp", "legit-corp.com", "github.com", "microsoft.com", "amazon.com"]); }
  function genFile() { return rand(["invoice.docm", "salary.xlsx", "payment.pdf", "remittance.exe", "report.zip", "quotation.jar"]); }
  function genPortList() { return rand(["22,3389,445", "80,443,8080", "1433,3306,5432", "21,23,25"]); }
  function genTime() {
    const h = String(randInt(0, 23)).padStart(2, "0");
    const m = String(randInt(0, 59)).padStart(2, "0");
    const s = String(randInt(0, 59)).padStart(2, "0");
    return "2026-10-28 " + h + ":" + m + ":" + s;
  }

  /* ---------- SOC Triage Simulator ---------- */
  const BASE_ESCALATE = [
    function () {
      const ip = genIP();
      const user = genUser();
      const fails = randInt(12, 120);
      return {
        title: "Successful login after brute force",
        desc: "User " + user + " had " + fails + " failed login attempts from " + ip + ", then one successful login.",
        logs: genTime() + " auth-fail user=" + user + " src=" + ip + "\n... (" + fails + " failures) ...\n" +
              genTime() + " auth-success user=" + user + " src=" + ip + " mfa=none",
        action: "escalate",
        reason: "Brute-force pattern followed by a successful authentication is a strong indicator of account compromise. Escalate for containment and password reset."
      };
    },
    function () {
      const user = genUser();
      const file = genFile();
      return {
        title: "Office app spawned PowerShell",
        desc: "User " + user + " opened " + file + " from an external email; winword.exe immediately started an encoded PowerShell process.",
        logs: genTime() + " process-create parent=winword.exe child=powershell.exe user=" + user + "\n" +
              genTime() + " powershell cmd='powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUA...'",
        action: "escalate",
        reason: "Office documents launching encoded PowerShell is a classic malware delivery chain. Escalate for host isolation and forensic imaging."
      };
    },
    function () {
      const host = genHost();
      const count = randInt(20, 200);
      return {
        title: "DNS queries to DGA domains",
        desc: "Endpoint " + host + " made " + count + " DNS queries to random-looking .xyz domains in a short window.",
        logs: genTime() + " dns-query host=" + host + " name=qxk7f2b.xyz\n" +
              genTime() + " dns-query host=" + host + " name=zz9plm4.xyz\n...",
        action: "escalate",
        reason: "High-volume queries to algorithmic domains suggest C2 beaconing. Escalate for host isolation and DNS forensics."
      };
    },
    function () {
      const host = genHost();
      const domain = rand(["evil-c2.xyz", "phish-login.tk", "badsite.kp"]);
      return {
        title: "Outbound connection to suspicious domain",
        desc: "Host " + host + " established repeated HTTPS sessions to " + domain + " every 60 seconds.",
        logs: genTime() + " proxy-allow src=" + host + " dst=" + domain + ":443 bytes=240\n" +
              genTime() + " proxy-allow src=" + host + " dst=" + domain + ":443 bytes=260\n...",
        action: "escalate",
        reason: "Regular beaconing to a suspicious domain is characteristic of command-and-control traffic. Escalate for host containment."
      };
    },
    function () {
      const user = genUser();
      const domain = rand(["evil-c2.xyz", "malware-drop.ru", "phish-login.tk"]);
      const file = genFile();
      return {
        title: "User downloaded executable from external site",
        desc: "User " + user + " downloaded " + file + " from " + domain + " and executed it.",
        logs: genTime() + " proxy-allow user=" + user + " url=http://" + domain + "/" + file + "\n" +
              genTime() + " process-create user=" + user + " path=Downloads\\" + file,
        action: "escalate",
        reason: "Downloading and executing files from untrusted domains is a common malware vector. Escalate for endpoint investigation."
      };
    }
  ];

  const ADV_ESCALATE = [
    function () {
      const user = genUser();
      return {
        title: "New local administrator account",
        desc: "User " + user + " created a new local account 'support_01' and added it to the Administrators group.",
        logs: genTime() + " user-create user=" + user + " account=support_01\n" +
              genTime() + " group-change user=" + user + " account=support_01 group=Administrators",
        action: "escalate",
        reason: "Unauthorized local admin creation is a persistence technique. Escalate for account review and possible incident response."
      };
    },
    function () {
      const host = genHost();
      const ip = genIP();
      return {
        title: "Outbound SMB to external IP",
        desc: "Host " + host + " attempted SMB file shares over port 445 to " + ip + ".",
        logs: genTime() + " firewall-alert src=" + host + " dst=" + ip + ":445 proto=smb action=allowed bytes=12MB",
        action: "escalate",
        reason: "SMB to an external host is highly abnormal and may indicate data exfiltration. Escalate immediately."
      };
    },
    function () {
      const host = genHost();
      return {
        title: "LSASS memory access",
        desc: "Process " + rand(["procdump.exe", "mimikatz.exe", "taskmgr.exe"]) + " accessed LSASS memory on " + host + ".",
        logs: genTime() + " sensitive-access host=" + host + " target=lsass.exe source=" + rand(["procdump.exe", "mimikatz.exe"]),
        action: "escalate",
        reason: "LSASS access is a classic credential-dumping indicator. Escalate for host isolation and forensic collection."
      };
    },
    function () {
      const host = genHost();
      const ip = genIP();
      return {
        title: "Firewall allowed inbound RDP",
        desc: "Firewall allowed an inbound RDP session to " + host + " from " + ip + ".",
        logs: genTime() + " firewall-allow src=" + ip + ":3389 dst=" + host + " proto=rdp action=allowed",
        action: "escalate",
        reason: "Inbound RDP from an external IP is a major exposure. Even if authenticated, escalate for access review."
      };
    }
  ];

  const BASE_DISMISS = [
    function () {
      return {
        title: "Scheduled backup completed",
        desc: "The nightly database backup job ran successfully from the backup service account.",
        logs: genTime() + " backup-job db-backup status=success duration=" + randInt(5, 30) + "m account=svc-backup",
        action: "dismiss",
        reason: "Expected scheduled maintenance. No security relevance."
      };
    },
    function () {
      const ip = genIP();
      const count = randInt(500, 5000);
      return {
        title: "Inbound port scan blocked",
        desc: "Firewall blocked ~" + count + " SYN packets from " + ip + " across common ports.",
        logs: genTime() + " firewall drop src=" + ip + " proto=tcp ports=" + genPortList() + " count=" + count + " action=blocked",
        action: "dismiss",
        reason: "Attack was blocked at the perimeter. No internal compromise indicated — log for trending, but no escalation needed."
      };
    },
    function () {
      const host = genHost();
      return {
        title: "Antivirus update success",
        desc: "Endpoint " + host + " downloaded the latest antivirus definitions.",
        logs: genTime() + " av-update host=" + host + " status=success signatures=20261028.001",
        action: "dismiss",
        reason: "Normal security hygiene event."
      };
    },
    function () {
      const user = genUser();
      return {
        title: "Successful login from known device",
        desc: "User " + user + " logged in from a known device during business hours.",
        logs: genTime() + " auth-success user=" + user + " src=10.0.1.42 device=trusted mfa=yes",
        action: "dismiss",
        reason: "Routine authentication with MFA from a trusted internal device."
      };
    },
    function () {
      const host = genHost();
      return {
        title: "High CPU on server",
        desc: "Host " + host + " reported sustained CPU usage from a known backup indexing task.",
        logs: genTime() + " perf-alert host=" + host + " process=backup-indexer cpu=92% duration=10m",
        action: "dismiss",
        reason: "Performance alert from a known legitimate process. Route to infrastructure team, not security."
      };
    }
  ];

  const ADV_DISMISS = [
    function () {
      const host = genHost();
      return {
        title: "Windows update installed",
        desc: "Host " + host + " installed routine Windows security patches.",
        logs: genTime() + " os-update host=" + host + " kb=KB5034441 status=success",
        action: "dismiss",
        reason: "Expected patch management activity."
      };
    },
    function () {
      const user = genUser();
      return {
        title: "User accessed internal file share",
        desc: "User " + user + " opened a folder on the internal finance share.",
        logs: genTime() + " file-access user=" + user + " path=\\\\fileserver\\finance\\reports src=10.0.1.15",
        action: "dismiss",
        reason: "Normal internal file access with no anomalous pattern."
      };
    }
  ];

  let triageIndex = 0;
  let triageScore = 0;
  let triageStreak = 0;
  let triageBest = 0;
  let triageAnswered = false;
  let currentAlert = null;

  function getLevel() { return Math.floor(triageScore / 5) + 1; }

  function generateAlert() {
    const level = getLevel();
    const escalatePool = BASE_ESCALATE.concat(level >= 2 ? ADV_ESCALATE : []);
    const dismissPool = BASE_DISMISS.concat(level >= 2 ? ADV_DISMISS : []);
    const pool = Math.random() < 0.5 ? escalatePool : dismissPool;
    return rand(pool)();
  }

  function renderTriage() {
    currentAlert = generateAlert();
    triageIndex += 1;
    document.getElementById("triageCounter").textContent = "Alert #" + triageIndex;
    document.getElementById("triageScore").textContent = "Score: " + triageScore;
    document.getElementById("triageStreak").textContent = "Streak: " + triageStreak;
    document.getElementById("triageHigh").textContent = "Best: " + triageBest;
    document.getElementById("triageLevel").textContent = "Level " + getLevel();
    document.getElementById("triageTitle").textContent = currentAlert.title;
    document.getElementById("triageDesc").textContent = currentAlert.desc;
    document.getElementById("triageLogs").textContent = currentAlert.logs;
    document.getElementById("triageFeedback").hidden = true;
    document.getElementById("btnNextAlert").hidden = true;
    document.getElementById("btnEscalate").disabled = false;
    document.getElementById("btnDismiss").disabled = false;
    triageAnswered = false;
  }

  function answerTriage(action) {
    if (triageAnswered || !currentAlert) return;
    triageAnswered = true;
    const correct = action === currentAlert.action;
    if (correct) {
      triageScore += 1;
      triageStreak += 1;
      if (triageStreak > triageBest) triageBest = triageStreak;
    } else {
      triageStreak = 0;
    }

    const fb = document.getElementById("triageFeedback");
    fb.hidden = false;
    fb.className = "feedback " + (correct ? "ok" : "bad");
    fb.textContent = (correct ? "Correct. " : "Not quite. ") + currentAlert.reason;
    document.getElementById("btnEscalate").disabled = true;
    document.getElementById("btnDismiss").disabled = true;
    document.getElementById("triageScore").textContent = "Score: " + triageScore;
    document.getElementById("triageStreak").textContent = "Streak: " + triageStreak;
    document.getElementById("triageHigh").textContent = "Best: " + triageBest;
    document.getElementById("triageLevel").textContent = "Level " + getLevel();

    const next = document.getElementById("btnNextAlert");
    next.hidden = false;
    next.textContent = "Next alert";
    next.onclick = renderTriage;
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
