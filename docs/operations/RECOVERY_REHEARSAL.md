# Recovery rehearsal

Run this rehearsal at least one week before the event and repeat it after any change to backup, state, authentication, or deployment code. Use a rehearsal state—not the final clean exercise state.

## Objectives

- Prove automatic backups are current and readable.
- Prove a known snapshot restores the clock, team decisions, journal, bookmarks, and facilitator observations.
- Prove Kusto remains available because exercise state restoration does not rebuild telemetry.
- Record the actual recovery time and assign the person authorised to make the restore decision.

## Procedure

1. Run the health and smoke tests.
2. Start a rehearsal, make a clearly labelled Alpha journal entry and facilitator observation, and activate one incident.
3. Trigger a manual backup and record its absolute filename.
4. Make a second clearly labelled change after the backup.
5. Stop the application and restore the recorded snapshot. The restore tool creates a rollback copy of the state it replaces.
6. Start the application and run both checks again.
7. Confirm the pre-backup entries returned, the post-backup change is absent, team isolation remains intact, and System readiness reports the expected non-clean rehearsal state.
8. Restore the approved clean-state backup and confirm all readiness checks are green.

```bash
cd /home/ubuntu/tabletop-siem
.venv/bin/python deployment/health_check.py
sudo .venv/bin/python deployment/smoke_test.py --env-file /etc/tabletop-siem.env
sudo systemctl start tabletop-siem-backup.service
ls -lt /home/ubuntu/tabletop-backups/*.db | head
sudo systemctl stop tabletop-siem
.venv/bin/python -m deployment.restore_state /home/ubuntu/tabletop-backups/SELECTED_BACKUP.db
sudo systemctl start tabletop-siem
.venv/bin/python deployment/health_check.py
sudo .venv/bin/python deployment/smoke_test.py --env-file /etc/tabletop-siem.env
```

## Acceptance record

Record the rehearsal date, operators, selected backup, rollback backup, recovery duration, deployed Git commit, checks performed, defects found, and corrective actions. A rehearsal is not complete until the final clean-state readiness screen is fully green.

