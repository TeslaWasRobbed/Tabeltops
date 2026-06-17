# Facilitator Debrief & Talking Points

> **Use this guide during the 11:45 Joint Lessons Learned session.** It contains the exact narrative, explanations for the tricky parts, and a "cheat sheet" for answering challenging questions from analysts who might have jumped to the wrong conclusions.

---

## 1. The True Narrative (What Actually Happened)

*Read or summarise this to the room to set the baseline.*

"At 09:10, Jordan Velez ran an `npm install` for a package called `@labdev/telemetry-helper`. However, instead of the official registry, the command explicitly pulled from an unapproved registry: `pkg-cache-lab.invalid`. 

This was a supply-chain compromise. The package contained a malicious `postinstall.js` script. When npm ran the postinstall step, it spawned `cmd.exe`, which launched an encoded PowerShell command. That command dropped and executed a secondary script called `collect.ps1`.

`collect.ps1` used `tar.exe` to archive local project files—specifically `.env.local`—into a staging file called `bundle.zip` in the Temp directory. 

The script then attempted to phone home. It successfully made a C2 connection to `update-cdn-lab.example`, sending about 2KB of data (likely a check-in or registration). However, when it attempted to actually upload the staged data to `exfil-gateway-lab.invalid`, the connection was **blocked by Network Protection**.

About 45 minutes later, Jordan legitimately accessed SharePoint via Chrome and downloaded a file called `CustomerAnalytics_Q2_Draft.xlsx`. Because the file had a 'Customer Data' sensitivity label, Defender for Cloud Apps flagged it as an unusual download. **This was normal user behaviour, not the malware stealing data.**"

---

## 2. Addressing the Red Herrings

*Ask the teams: "Who investigated the CEO, Cato Syversen?" or "Who looked into the AI trial email?" Then reveal the truth.*

* **Cato's Impossible Travel:** "Cato signed in from Cardiff, then Dublin 85 minutes later. If you looked at the `Status` or `AuthenticationDetails` in `SigninLogs_CL`, you would see it was a Cisco AnyConnect VPN session. This was benign."
* **Cato's Spoofed Emails:** "There were 50 emails claiming to be from Cato. If you checked `EmailEvents_CL`, they all failed SPF, DKIM, and DMARC, and were routed to Junk. It was just background spam."
* **The AI Trial Email:** "Arrived at 08:35. It was a real marketing email, but there is zero process lineage connecting an email client or browser to the `npm install` that happened 35 minutes later."
* **The Disabled Contractor:** "Failed sign-ins for `t.oconnor.contractor`. Just routine internet credential spraying against a disabled account."

---

## 3. Anticipated Questions & Rebuttals (Your Cheat Sheet)

If teams argue their (incorrect) findings, use these rebuttals:

**Q: "But data DID leave the network! Look at the connection to `update-cdn-lab.example`!"**
> **Your response:** "Did you check the `AdditionalFields` for that network event? It shows `BytesOut: 2048`. 2KB is the size of a C2 beacon or a registration handshake, not an exfiltration of a zipped repository. The actual exfiltration destination (`exfil-gateway-lab.invalid`) has an `ActionType` of `ConnectionFailed` and was blocked."

**Q: "The malware stole the Customer Analytics file!"**
> **Your response:** "Look at the timeline. The malware executed and staged the `.env.local` file at 09:15. The SharePoint download didn't happen until 09:58. Furthermore, if you look at `DeviceFileEvents_CL` for the `.xlsx` file, the `InitiatingProcessFileName` is `chrome.exe`, not PowerShell, and `AdditionalFields` explicitly states it was a local browser download."

**Q: "We declared a Critical breach because Customer Data was involved."**
> **Your response:** "It's good that you identified the Customer Data label. However, as analysts, we must distinguish between *data accessed on a compromised machine* and *data successfully exfiltrated*. Because the exfil was blocked, and the cloud download was a legitimate user action, we have a *potential exposure* requiring IR forensics, but we do not have a confirmed data breach. Over-declaring causes unnecessary panic and legal triggers."

**Q: "The initial access was phishing via the AI trial email."**
> **Your response:** "In incident response, we need hard evidence linking events. Was there a process tree showing Outlook or Chrome spawning a malicious payload at 08:35? No. The execution started cleanly at 09:10 with a developer manually running `npm install`. Correlation does not equal causation."

---

## 4. Joint Lessons Learned (Discussion Prompts)

*Use these to guide the final 10 minutes of discussion.*

1. **Supply Chain Defenses:** "How do we prevent developers from overriding the npm registry in the CLI? Should we enforce registry pinning at the firewall or proxy level?"
2. **Postinstall Scripts:** "npm postinstall scripts run with the privileges of the user. Should we disable them globally (`npm config set ignore-scripts true`) and only allow them on a case-by-case basis?"
3. **Endpoint vs. Cloud Correlation:** "This scenario had a real endpoint compromise and a scary-looking cloud alert happen on the same day. How can our SOC processes ensure we don't automatically assume two bad things are part of the same kill chain without checking the timestamps and processes?"
4. **Anti-Forensics:** "The malware deleted `collect.ps1` after running it. If this wasn't captured in the SIEM logs, how else would we recover it? (Answer: EDR file quarantine, Volume Shadow Copies, memory forensics)."