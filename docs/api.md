# Automating OpenCVEC with the API

Everything the interface does goes through the JSON API under `/api/`. To use it from a script or a CI job, create a personal token in **My account › API tokens**, then send it in the `Authorization` header.

```sh
export OPENCVEC=https://opencvec.example.com
export TOKEN=ocv_…   # shown once at creation

# List assets and their ownership status
curl -s -H "Authorization: Bearer $TOKEN" "$OPENCVEC/api/assets" | jq '.[] | {id, host, owned}'

# Launch Log4Shell and Text4Shell on asset 3
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"asset_id": 3, "target_url": "https://erp.example.com/api/search", "checkers": ["log4shell", "text4shell"]}' \
  "$OPENCVEC/api/campaigns"

# Follow the campaign until no check is pending, then read the verdicts
curl -s -H "Authorization: Bearer $TOKEN" "$OPENCVEC/api/campaigns/42" | jq '{pending, checks: [.checks[] | {checker, verdict, summary}]}'

# Generate a PDF report and download it
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"campaign_id": 42, "format": "pdf", "include_raw": true}' "$OPENCVEC/api/reports"
curl -s -H "Authorization: Bearer $TOKEN" -o report.pdf "$OPENCVEC/api/reports/7/download?download=1"
```

## Rules

- A token has the role of its owner (viewer, analyst, administrator), and its owner's rights change with the account.
- It can expire (0 to 730 days) and can be revoked at any time. Only its SHA-256 hash is stored.
- It cannot create or revoke tokens, change the password or manage two-factor authentication. Those actions require an interactive session.
- Requests with a token do not need the `X-OpenCVEC` anti-CSRF header, which is only required for browser sessions.
- Every action is written to the audit log under the owner's identity, exactly as from the interface.
- Unknown JSON fields are rejected. In particular, a campaign accepts no payload or callback URL: only an asset, a target URL within that asset, and checker identifiers.

## Main endpoints

| Method and path | Role | Purpose |
|---|---|---|
| `GET /api/health` | none | status and version |
| `GET /api/checkers` | viewer | catalog (installed plugins) |
| `GET /api/assets`, `POST /api/assets`, `POST /api/assets/{id}/verify` | viewer / analyst | assets and proof of ownership |
| `POST /api/assets/{id}/canary` | analyst | generate the canary file |
| `POST /api/campaigns`, `GET /api/campaigns/{id}` | analyst / viewer | launch and follow checks |
| `GET /api/checks/{id}` | viewer | verdict, proof and callbacks of one check |
| `GET /api/schedules`, `POST /api/schedules` | viewer / analyst | scheduled checks |
| `GET /api/callbacks?status=alerts` | viewer | honeytoken alerts |
| `POST /api/reports`, `GET /api/reports/{id}/download` | analyst / viewer | PDF, HTML or JSON reports |
| `GET /api/audit/verify` | administrator | audit chain integrity |
