<p align="center">
  <img src="assets/logo-v2.svg" width="110" alt="HardenForge">
</p>

<h1 align="center">HardenForge</h1>

<p align="center">Audit a Linux machine's security configuration against YAML rules, keep the evidence, and track the score over time.</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="MIT license" src="https://img.shields.io/badge/license-MIT-green">
</p>

HardenForge reads system settings (sshd config, sysctl values, file permissions and so on), compares them with rules
you define, and stores what it found next to each result. It never changes the machine. A small web dashboard
shows the results, and reports can be exported as HTML, CSV or JSON.

Right now it audits Linux only, and the rules that ship with it are examples you are expected to edit or replace.

## Install

Python 3.11 or newer.

```bash
git clone https://github.com/Retr0Kali/hardenforge.git
cd hardenforge
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Usage

### Command line

```bash
python -m sentinel audit --rules rules                 # readable output
python -m sentinel audit --rules rules --format json   # JSON
python -m sentinel audit --rules rules --save          # also store the scan in data/sentinel.db
```

Run it with `sudo` if you want it to read files that only root can read. Without that, those checks end as `ERROR`
(permission denied) instead of being guessed.

### Dashboard

```bash
export SENTINEL_API_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
echo "$SENTINEL_API_TOKEN"
uvicorn --factory sentinel.api:create_app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/, paste the token and press **Scan this host**. If the port is taken, pick another one.
The server won't start without a token, and it should stay on 127.0.0.1 unless you put TLS in front of it.

The dashboard shows a score card per scanned machine, a breakdown of outcomes, L1/L2 scores, a trend line, open
findings by severity, and a searchable findings table. Clicking a finding shows the raw evidence and the fix
guidance for that rule. The report buttons export the selected scan.

### Scheduled scans

```cron
0 2 * * * cd /opt/hardenforge && . .venv/bin/activate && SENTINEL_DATA_DIR=/var/lib/hardenforge python -m sentinel audit --rules rules --save
```

### Other machines

Run the audit on the other machine, then send the JSON to your server:

```bash
python -m sentinel audit --rules rules --format json > scan.json
curl -X POST https://your-server/ingest \
  -H "Authorization: Bearer $SENTINEL_API_TOKEN" \
  -H "Content-Type: application/json" -d @scan.json
```

Those scans are labelled as unverified, and the server works out the score itself instead of trusting the file.

## Rules

Rules are YAML files under `rules/`. One rule looks like this:

```yaml
- id: SH-LNX-SSH-001
  title: SSH root login is disabled
  description: sshd should not permit direct root login.
  platforms: [linux]
  severity: high              # low, medium, high, critical
  status: approved            # only approved rules are run
  profile: L1                 # optional, L1 or L2
  provenance: {kind: community, source: my-baseline, version: "1.0"}
  check:
    type: config_kv
    params:
      path: /etc/ssh/sshd_config
      key: PermitRootLogin
      op: in
      value: ["no"]
      default: prohibit-password
      stop_at_regex: '^match\b'
      missing_file: not_applicable
  remediation: Set "PermitRootLogin no", test with `sshd -t`, then reload sshd.
  rollback: Restore the backed-up sshd_config and reload sshd.
  impact: Direct root SSH logins stop working.
```

Available checks:

- `config_kv` reads a key from a config file (space or `=` separated). The first match wins, like sshd.
- `file_permission` checks the maximum mode and, optionally, the owner UID.
- `sysctl` reads a kernel parameter from `/proc/sys`.
- `command_output` runs one of a short list of read-only programs (no shell) and matches the exit code or output.
- `manual` always reports `MANUAL_REVIEW` and shows your instructions.

Possible results are `PASS`, `FAIL`, `NOT_APPLICABLE`, `NOT_CHECKED`, `ERROR` and `MANUAL_REVIEW`. A rule file that
fails validation is listed as a load error. It is not skipped quietly. Rules with `kind: ai_draft` stay as
`NOT_CHECKED` until someone reviews them and sets `status: approved`.

## Scoring

```
score    = PASS / (PASS + FAIL)
coverage = (PASS + FAIL) / all rules except NOT_APPLICABLE
```

`ERROR`, `NOT_CHECKED` and `MANUAL_REVIEW` are never counted as passes and are shown separately. The score only
describes the rules you ran. It says nothing about the overall security of the machine.

## Configuration

Environment variables (see `.env.example`):

| Variable | Purpose |
|---|---|
| `SENTINEL_API_TOKEN` | Required for the API and dashboard, at least 16 characters |
| `SENTINEL_DATA_DIR` | Location of `sentinel.db` and the encrypted key store (default `./data`) |
| `SENTINEL_RULES_DIR` | Rules directory (default `./rules`) |
| `SENTINEL_MASTER_KEY` | Fernet key used to encrypt stored provider keys; keep it outside the data directory |
| `SENTINEL_AI_SHARING` | Data categories allowed to be sent to an AI provider (default: none) |
| `SENTINEL_<PROVIDER>_API_KEY`, `_MODEL` | Optional; provider is `GEMINI`, `OPENAI` or `ANTHROPIC` |

## HTTP API

Everything except `/` and `/health` needs an `Authorization: Bearer <token>` header.

```
GET    /                         dashboard
GET    /health
GET    /system                   detected OS info
POST   /audit                    run and store a local audit
POST   /ingest                   store results from another host
GET    /scans                    latest scan per machine
GET    /scans/{id}               results, L1/L2 scores and history
GET    /scans/{id}/report        ?format=html|csv|json
GET    /providers                AI provider status, keys masked
PUT    /providers/{name}/key     save a key
DELETE /providers/{name}/key     remove a key
```

## AI providers

`src/sentinel/ai/` contains adapters for Gemini, OpenAI and Anthropic behind one manager. It checks that you have
allowed the kind of data being sent, redacts keys, IPs, emails and usernames from the prompt, retries, falls back to
another provider, applies request and cost limits, and tracks usage (cost is only an estimate from the prices you
configure). Answers are plain text for a human to read. They never change a result and are never executed. The
dashboard only manages the keys for now; it doesn't call the manager yet.

## Security notes

- Rule files are parsed with `yaml.safe_load`, validated against a strict schema, and size-limited.
- Commands are run as argument lists without a shell, from a fixed allow-list of read-only programs.
- Paths in rules are resolved inside the audit root, so `../` tricks end as `ERROR`.
- Provider keys come from the environment or a Fernet-encrypted file. The API only ever returns them masked.
- The dashboard renders evidence as text, sends a strict CSP, and exported HTML and CSV are escaped.
- Known gaps: one shared token instead of user accounts, no built-in TLS, no persistent audit log, rules are not signed.

## Layout

```
assets/            logo and social preview images
rules/linux/       example rules
src/sentinel/      application code (api, engine, checks, scoring, storage, report, ai/)
tests/             pytest suite
docs/              architecture and threat model notes
```

The Python package is still called `sentinel`; the project name is HardenForge.

## Limitations

- Linux only for now, and it only reads; it does not apply fixes. The remediation text is guidance for a person.
- The bundled rules are examples written for this project. They are not CIS content and carry no CIS control IDs.
- CIS and CIS Benchmarks are trademarks of the Center for Internet Security, which is not affiliated with this project. Use official benchmark material under its own license.
- Only audit systems you own or have permission to assess.

## Contributing

Pull requests are welcome. Please include tests for new checks (`tests/test_core.py` shows how to test against a
temporary root directory) and don't run destructive tests on your own machine. For security problems, see
[SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
