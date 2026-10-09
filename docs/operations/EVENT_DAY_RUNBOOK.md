# TabletopSIEM event-day runbook

This runbook is for the facilitator operating the five-hour Team Alpha/Team Bravo exercise. Complete the preflight before participants are admitted. Do not rebuild Kusto or reset the application after teams begin work unless the recovery procedure explicitly requires it.

## One working day before

1. Confirm the VM, `kusto-emulator`, `tabletop-siem`, and `tabletop-siem-backup.timer` are running.
2. Confirm the application is at the approved Git commit and the worktree is clean.
3. Run the deployment health check and authenticated smoke test.
4. Open the facilitator page and run **System readiness**. Every check must be green.
5. Confirm the clock reads `T+00:00:00`, state is **Not started**, 30 historical incidents are visible, and neither team has day-of decisions, journal entries, or bookmarks.
6. Download and retain one clean-state backup outside the automatic rotation set.
7. Test the Alpha, Bravo, and facilitator access codes in separate private browser sessions. Do not share facilitator credentials with participants.

```bash
cd /home/ubuntu/tabletop-siem
git status --short
sudo systemctl is-active tabletop-siem
sudo docker inspect --format '{{.State.Status}}' kusto-emulator
sudo systemctl is-active tabletop-siem-backup.timer
.venv/bin/python deployment/health_check.py
sudo .venv/bin/python deployment/smoke_test.py --env-file /etc/tabletop-siem.env
sudo systemctl start tabletop-siem-backup.service
```

## 30 minutes before

- Put the facilitator view on a dedicated device and keep a terminal connected to the VM.
- Sign Team Alpha and Team Bravo into different browsers or browser profiles.
- Run **System readiness** again and note the time in facilitator observations.
- Confirm exports download from the browser and the latest backup passes the readiness check.
- Remind participants that this is fictional training data and state the organisation's rule on external AI tools explicitly.

## Starting the exercise

1. Give the participant briefing and confirm both teams can see historical incidents, Logs, Journal, Bookmarks, and FreshService.
2. Press **Start exercise** once. Buttons are locked while the request is processed.
3. Verify all three views show the same moving exercise clock.
4. Do not announce alert timings. The first day-of incident is scheduled for `T+00:05:00`.

## During the exercise

- Record observations privately in the facilitator view; avoid coaching unless required by the exercise rules.
- Use **Pause** for a genuine break or technical interruption. Record why and when it was paused.
- Treat the persistent red connection banner as an operational fault. Check both services before asking analysts to retry.
- Do not edit Kusto data, SQLite state, the scenario manifest, or system time during play.
- The 15-minute backup timer should remain active throughout the exercise.

Useful checks:

```bash
sudo systemctl is-active tabletop-siem
sudo docker inspect --format '{{.State.Status}}' kusto-emulator
.venv/bin/python deployment/health_check.py
sudo journalctl -u tabletop-siem -n 80 --no-pager
systemctl list-timers tabletop-siem-backup.timer --no-pager
```

## Fault decision guide

| Condition | Action |
| --- | --- |
| One browser fails but health is green | Refresh or sign in again; do not pause unless the team is materially disadvantaged. |
| Application unavailable to multiple users | Pause when possible, check `tabletop-siem`, then restart the service. |
| Kusto unavailable | Pause, check `kusto-emulator`, restart it if stopped, then run the health check. |
| Incorrect analyst action | Do not alter it; the audit trail and report are part of the assessment evidence. |
| Accidental reset or corrupt state | Keep the exercise stopped and follow `RECOVERY_REHEARSAL.md`. |

## Closing the day

1. Pause the exercise at the agreed reporting deadline if it has not completed automatically.
2. Export the facilitator grading pack before any reset.
3. Confirm both team HTML reports, combined decisions CSV, raw audit JSON, and facilitator observations are present.
4. Trigger a final backup and copy the grading pack and backup to the approved evidence location.
5. Record the deployed commit, exercise clock, any pauses, and technical issues.
6. Reset only after the evidence has been secured and a second facilitator has confirmed it is safe.

