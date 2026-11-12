# Prototype methodology

This page describes the original Tuesday prototype. The [corrected-source study](corrected_study.md) has a separate registered protocol, whole-window/episode checks and versioned result workflow. It does not retroactively change the prototype's split or experiment identity.

## Clock handling

The local Tuesday source contains minute-resolution timestamps such as `4/7/2017 8:54`, followed by noon and low-hour values with no AM/PM. The parser uses day/month/year, preserves the original text, and **does not add 12 hours** to any record.

All valid rows remain in `flow`. Only records with reported start hour 8–11 and an inferred end before noon on the same day enter temporal features. Interpreting those values as morning relies on the documented daytime capture and the observed file start; it is a limited capture-clock assumption, not verified timezone information. Hours 1–7 and 12 are excluded from temporal scoring rather than repaired using attack labels. Afternoon SSH records remain available for non-temporal audit counts, not scored results.

The availability proxy is minute-rounded reported start plus duration in microseconds. True start may differ within the reported minute, so window boundaries are uncertain. These are retrospective flow summaries, not real-time detections or measured detection delays. Unknown/invalid required timestamps are quarantined.

## Development allocation

The committed `configs/prototype.yaml` uses Tuesday morning-clock intervals:

| Role | Half-open interval |
|---|---|
| Training and benign rule reference | 08:55–09:45 |
| Cutoff calibration | 09:45–10:00 |
| Development check | 10:00–11:00 |

All selected intervals belong to development data. The FTP episode can span roles; correlated windows and repeated entity identity make any apparent success descriptive. The final five-day evaluation protocol is not implemented or claimed. The real loader permits Tuesday only and refuses Friday.

## Features and rules

Feature SQL contains no label joins. `window_labels.sql` builds targets independently: any known attack flow makes a positive window; unknown-label windows are excluded from metrics. Labels do not enter the ranking view.

Three SQL scores measure flow count, distinct destination ports (minimum 10 flows), and flows to ports 21/22. A scale is the larger of one and the training-benign 99th percentile. PostgreSQL computes each normalized score and their maximum. Separate component cutoffs and a joint cutoff are calibrated independently; a component alert does not imply the combined decision uses the same cutoff.

Rule scales and preprocessing use training data only. Final cutoffs use benign calibration windows, selecting the most permissive `score >= cutoff` that permits at most floor(0.01 × benign calibration count) false alerts. Ties are excluded as a group. An above-maximum cutoff may produce zero alerts. The development false-alert rate is reported even when it exceeds the calibration target.

The logistic baseline uses counts, bytes, packets, and mean duration; median imputation, `log1p`, scaling, and L2 logistic regression are fitted on training data only. `C=1`, balanced class weights, `lbfgs`, seed 1729, and maximum 2,000 iterations are fixed. Raw addresses, absolute clocks, labels, and history/cold-start features are excluded from ML. A flow-count baseline, seeded random score baseline, and always-benign sanity check share the same evaluation population. Undefined metrics remain blank/null rather than being reported as zero.

History covers preceding **active** windows in the previous 60 elapsed minutes and excludes the current/future window. Missing source windows are not fabricated zeros; complete sensor-coverage reconstruction is deferred. History is investigative only in this prototype.

## Reproducibility boundary

Each output directory records source hashes, configuration and SQL hashes, fitted cutoffs, a local fitted model, code/library versions, predictions, query results, and measured execution plans. Final-test sealing, hash-enforced test registration, confidence intervals, label sensitivity, artifact ablations, and before/after optimization experiments are later milestones. A recorded hash here documents provenance; it does not claim those final-study controls are implemented.

## References

- [Official CIC-IDS2017 dataset, topology, capture schedule, and citation](https://www.unb.ca/cic/datasets/ids-2017.html).
- Sharafaldin, Lashkari, and Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP 2018. The source files are not redistributed here.
- [Engelen, Rimmer, and Joosen: dataset and flow-processing defects](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html).
- [Psycopg COPY documentation](https://www.psycopg.org/psycopg3/docs/basic/copy.html).

