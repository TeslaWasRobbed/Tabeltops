# Scoring Rubric — Shadow AI / Supply-Chain Tabletop

**Total: 100 points** (adjust weightings to match session length)

## 1. Alert triage and prioritisation (15 points)

| Score | Criteria |
|-------|----------|
| 13–15 | Correctly prioritises execution/supply-chain alerts; deprioritises benign IDE/dotnet/peer npm; notes policy cloud alerts separately |
| 8–12 | Reasonable ordering with minor mis-prioritisation |
| 0–7 | Treats all alerts equally or chases email/leaver sign-in as primary |

## 2. Evidence-led investigation (15 points)

| Score | Criteria |
|-------|----------|
| 13–15 | Conclusions cite specific tables/fields; uses AlertEvidence joins; avoids alert-title-only reasoning |
| 8–12 | Mostly evidence-based with gaps |
| 0–7 | Speculative narrative without telemetry |

## 3. KQL / pivot quality (10 points)

| Score | Criteria |
|-------|----------|
| 9–10 | Effective pivots on DeviceName, AccountUpn, SystemAlertId, SHA256, NetworkMessageId, SessionId |
| 5–8 | Basic queries work; missed useful joins |
| 0–4 | Minimal or incorrect query usage |

## 4. Timeline construction (15 points)

| Score | Criteria |
|-------|----------|
| 13–15 | Ordered UTC timeline; npm install before PowerShell before network before cloud |
| 8–12 | Correct ordering with timestamp gaps |
| 0–7 | Missing critical events or wrong sequence |

## 5. Avoiding overclaiming (15 points)

| Score | Criteria |
|-------|----------|
| 13–15 | Clearly separates execution vs exfil vs breach; notes blocked connection |
| 8–12 | Some overstatement but self-corrects in report |
| 0–7 | Declares confirmed breach/exfil without proof |

## 6. Correct severity decision (10 points)

| Score | Criteria |
|-------|----------|
| 9–10 | Medium (or High with documented policy rationale); not Critical without cause |
| 5–8 | One level off with justification |
| 0–4 | Informational or Critical inappropriately |

## 7. Correct containment decision (10 points)

| Score | Criteria |
|-------|----------|
| 9–10 | Isolate host; preserve artifacts; scoped account actions; block domains |
| 5–8 | Partial containment plan |
| 0–4 | No isolation or excessive org-wide actions |

## 8. Policy / process awareness (5 points)

| Score | Criteria |
|-------|----------|
| 5 | References registry policy, AI tooling, Customer Data handling, escalation paths |
| 3 | Mentions one policy area |
| 0 | Ignores policy context |

## 9. Incident report quality (5 points)

| Score | Criteria |
|-------|----------|
| 5 | Complete template; executive-readable; consistent with findings |
| 3 | Partial template |
| 0 | Missing deliverable |

## 10. Lessons learned quality (5 points)

| Score | Criteria |
|-------|----------|
| 5 | Specific, actionable detection/process improvements |
| 3 | Generic statements |
| 0 | None provided |

---

## Bonus (+5 each, max +10)

- Identifies **canonical outcome C** with clear inconclusive boundaries
- Maps **MITRE** techniques to specific observables
- Documents **false leads ruled out** (email, VPN sign-in, disabled contractor)

## Penalties (-5 each)

- Declares **confirmed exfiltration** without network/DLP proof
- Names email as **root cause** without correlation
- Recommends **org-wide password reset** without justification

---

## Grading bands

| Total | Grade |
|-------|-------|
| 90–100+ | Outstanding — ready for live lead analyst shadowing |
| 75–89 | Proficient — solid SOC judgement |
| 60–74 | Developing — review pivot and calibration skills |
| &lt;60 | Remediation — repeat exercise with mentor |
