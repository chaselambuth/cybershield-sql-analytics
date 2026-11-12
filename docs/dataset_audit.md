# Local dataset audit — prototype

**November 8 update:** a separate corrected-source adapter audit and PostgreSQL study now cover Monday–Thursday. See [four-day support, source identities and limitations](corrected_study.md). The 1,552,419 accepted rows subsequently reconciled through SQL, and a separate registered comparison completed on later Wednesday/Thursday windows. Strict unknown-window exclusion limits attack-family coverage. The original Tuesday observations below remain historical and unchanged.

Audited October 24, 2026 (America/New_York). This document describes the original-release, Tuesday-only prototype. The executed [source-selection notebook](../notebooks/01_data_audit_and_source_selection.ipynb) now adds a complete Tuesday audit of the CNS2022 corrected release and recommends it for the next ingestion adapter. Full-week feasibility remains open; the active prototype continues using this original source.

## Source and scope

- Local artifact: `GeneratedLabelledFlows.zip` (original labeled-flow release), read in place without extraction.
- Archive size: **283,876,488 bytes**. Eight CSV members total **1,203,105,382 uncompressed bytes**. The archive also contains a directory entry.
- Selected member: `TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv` (the directory name includes a trailing space).
- Selected uncompressed size: **174,696,560 bytes**; header: **85 columns**.
- Selected-member SHA-256: `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`.
- File naming and schema match the original labeled-flow format. No independently published provider checksum was compared; this is local provenance, not an authenticity attestation.
- Friday contents were not ingested or scored. Only the archive member inventory was listed for the full week.

The original labeled-flow archive is documented by the [official CIC-IDS2017 source](https://www.unb.ca/cic/datasets/ids-2017.html). The official source requests citation; raw source data are excluded from Git. Review current terms before any future redistribution.

## Measured reconciliation

| Quantity | Count |
|---|---:|
| Input data records | 445,909 |
| Accepted normalized flows | 445,892 |
| Quarantined required-field errors | 17 |
| Accepted flows eligible for morning-clock temporal features | 207,006 |
| Repeated-content rows flagged and retained | 4 |
| Accepted benign labels | 432,057 |
| Accepted FTP-Patator labels | 7,938 |
| Accepted SSH-Patator labels | 5,897 |

The 17 rejected durations were sixteen `-1` values and one `-4`. These rejected records were benign-labeled; no attack-labeled record was rejected in this run. Reconciliation is exact: 445,892 + 17 = 445,909.

Each optional flow-rate column had 264 missing, nonfinite, or invalid values among accepted records. The rates are stored as null and are excluded from model features; packets/bytes remain available. `Fwd Header Length` appears twice and is mapped to distinct normalized names. The parser strips leading spaces without losing the original header.

Machine-readable counts, warnings, and rejection reasons are generated in [data_quality.json](../reports/prototype/data_quality.json); member/archive hashes and original headers also reside in PostgreSQL.

## Timestamp decision

Actual timestamps use day/month/year and minute precision, including values such as `4/7/2017 8:54`, `4/7/2017 12:00`, and `4/7/2017 1:00` without AM/PM. File order is not globally chronological. It cannot safely supply a simple monotonic repair rule.

The prototype performs no clock repair or timezone conversion. All accepted rows retain raw timestamp text and parsed reported-clock fields. Temporal features admit reported start hours 8–11 whose duration-derived end remains before noon on the same date. This limits scoring to a morning-clock interpretation consistent with the documented daytime capture; it does not resolve the afternoon or establish UTC. Minute precision also makes completion-window membership uncertain near boundaries.

## Scoring support and concentration

The usable morning population yields **11,398 active source windows** and **15 positive windows**, all associated with recorded source `172.16.0.1` and the FTP-Patator label. The firewall/NAT topology makes this address unsuitable as a claim about an individual attacker. [Official topology](https://www.unb.ca/cic/datasets/ids-2017.html)

| Development role | Known-label windows | Positive windows |
|---|---:|---:|
| Train, 08:55–09:45 | 3,493 | 6 |
| Calibration, 09:45–10:00 | 1,245 | 3 |
| Development check, 10:00–11:00 | 3,413 | 6 |
| Outside scored intervals | 3,247 | 0 |

Only the **1,242 benign calibration windows** set final cutoffs. Training, calibration, and development can share one FTP episode; they are not independent attack repetitions. The project therefore passes an end-to-end prototype gate, while the final study's independent-support and cross-day evaluation gates remain unresolved. SSH records with low-hour clocks are retained but excluded from scoring.

## Next audit decisions

1. Compare a documented corrected release with the local original within the planned time box.
2. Establish a label-independent full-day timestamp policy and capture-coverage model, or narrow the final study explicitly.
3. Compare source, destination, and pair scoring units without presenting repeated windows as independent attacks.
4. Finalize attempted/unknown labels, episode definitions, split isolation, and primary holdout support before fitting the final study.

