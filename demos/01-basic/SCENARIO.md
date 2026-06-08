# Demo 01 - Basic EDR coverage reconciliation

This demo reconciles three small inventories exported from a typical
Windows-shop blue-team stack:

| File        | Source                          | Format |
|-------------|---------------------------------|--------|
| `ad.csv`    | Active Directory computers      | CSV    |
| `mdm.json`  | MDM (Intune-style) devices      | JSON   |
| `edr.json`  | EDR sensor inventory            | JSON   |

## Run it

```bash
python -m edrgap scan --ad demos/01-basic/ad.csv \
                       --mdm demos/01-basic/mdm.json \
                       --edr demos/01-basic/edr.json
```

For pipeline/JSON output:

```bash
python -m edrgap scan --ad demos/01-basic/ad.csv \
                       --mdm demos/01-basic/mdm.json \
                       --edr demos/01-basic/edr.json --format json
```

## What you should see

The fleet has 6 distinct hosts across the three inventories:

* **WIN-FINANCE-01** - in AD + MDM, **no EDR record** -> `no_edr_coverage`
  (critical). This is the dangerous blind spot.
* **WIN-HR-02** - in all three, but its EDR agent status is `disabled`
  -> `agent_degraded` (high). Classic tamper/bypass signal.
* **WIN-DEV-03** - in all three, but EDR last check-in is ~30 days old
  -> `stale_checkin` (high). The sensor may be silenced.
* **LINUX-BUILD-09** - reports to EDR only, absent from AD + MDM
  -> `unmanaged_host` (medium). Rogue or decommissioned box still phoning home.
* **MAC-MKTG-04** - in MDM + EDR but not AD -> `missing_from_ad` (low),
  off-domain device.
* **WIN-CEO-01** - in all three, healthy, recent check-in -> no findings.

Because findings exist, the command exits **non-zero (1)**, which makes it
drop straight into a CI gate or a SOAR/cron job.
