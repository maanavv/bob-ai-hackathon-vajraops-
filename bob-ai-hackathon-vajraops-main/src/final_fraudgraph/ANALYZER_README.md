# FraudGraph — Investigation Analyzer

The normalizer remains the first stage. The analyzer is the second stage and consumes the normalized `case.json`.

## Pipeline

`case.json -> identity resolution -> subject profiles -> event timelines -> relationships -> pattern detection -> network -> case brief`

## Subject profile fields

Each entry in `subject_profiles` contains:

- `subject_id`
- `subject_type`
- `name`
- `role`
- `role_hypotheses[]`
- `identifiers.person_ids[]`
- `identifiers.account_ids[]`
- `identifiers.account_numbers[]`
- `identifiers.upi_ids[]`
- `identifiers.upi_vpas[]`
- `identifiers.phone_ids[]`
- `identifiers.phone_numbers[]`
- `identifiers.sim_ids[]`
- `identifiers.imsis[]`
- `identifiers.imeis[]`
- `identifiers.observed_imeis[]` / `observed_imsis[]` when extended in future data
- `identifiers.device_ids[]`
- `identifiers.ip_ids[]`
- `identifiers.ip_addresses[]`
- `identifiers.location_ids[]`
- `identifiers.emails[]`
- `identity_evidence[]`
- `evidence_ids[]`
- `statistics{}`
- `transactions[]`
- `calls[]`
- `sms[]`
- `web_activity[]`
- `sim_events[]`
- `timeline[]` — newest to oldest
- `relationships[]`

Every timeline event keeps the original normalized event fields inside `details` and the originating `source_evidence_ids` in `evidence_ids`.

## Built-in detection

The current rule layer detects:

- `RAPID_FAN_OUT`
- `RAPID_FAN_IN`
- `CIRCULAR_MONEY_FLOW`
- `SHARED_DEVICE`
- `SHARED_IP`
- `SIM_SWAP_PRECEDES_TRANSACTION`

Role hypotheses are evidence-driven and are kept separate from source-record roles.

## Web/website compatibility

The analyzer accepts `web_activity` and compatible collections such as `websites`, `browser_history`, `browsing_history`, `urls`, `url_logs`, `web_logs`, and `http_logs`. Supported web fields include URL/domain, timestamp, activity type, HTTP method/status, person, device, phone and IP identifiers.

## CLI

```bash
python analyze_json.py data/cases/001/normalized/case.json
```

Or:

```bash
python analyze_json.py path/to/case.json -o path/to/case_analysis.json
```

## Important normalization change

Version `1.1` preserves source-provided IDs instead of overwriting them with generated IDs and stores each raw source row under its evidence record. This is required for strong forensic provenance and lets the analyzer reconstruct person mappings from mixed source files.

Re-run normalization once with the updated normalizer before using older `schema_version: 1.0` `case.json` files as your primary demo input.

## Final investigation visualizer

The Streamlit `Analysis Result -> Graph — Phase 3` tab is now the final interactive visualization layer over the analyzer output.

- Entity nodes are built directly from `entity_relationships` and `subject_profiles`.
- Relationships are intentionally rendered as undirected investigation edges.
- Clicking an edge resolves its `evidence_ids` back to the analyzer timeline and exposes linked call logs and transaction records.
- Clicking a person shows the analyzer's exact `timeline`, newest to oldest.
- Clicking technical entities such as PHONE, ACCOUNT, DEVICE, SIM, IMEI or IP searches the preserved event details and reconstructs their chronological evidence history without changing the source analysis.
- Search and filters support entity type, relationship type, and call/transaction evidence.
- The visualizer is presentation-oriented with a white forensic workspace and a persistent detail panel.
