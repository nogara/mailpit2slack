# Mailpit to Slack OTP Forwarder

A small Go service that polls a Mailpit instance for OTP emails and forwards the extracted code and recipient to a Slack channel via an incoming webhook.

It can also run an optional heartbeat flow: send an email through SMTP to `heartbeat@example.com`, confirm that it reached Mailpit, delete the heartbeat message, and persist the service state as `up`, `warning`, or `down`.

## Configuration

Copy `.env.example` to `.env` (or set the variables directly):

- `MAILPIT_URL` (required): Base URL of the Mailpit server.
- `MAILPIT_USERNAME` / `MAILPIT_PASSWORD`: Optional basic auth credentials.
- `MAILPIT_SEARCH_QUERY`: String passed to Mailpit `/api/v1/search` to scope messages (e.g., recipient email or domain). Falls back to `TEST_EMAIL_DOMAIN`.
- `SLACK_WEBHOOK_URL` (required): Slack incoming webhook URL.
- `IGNORED_EMAIL_ADDRESSES`: Optional comma-, semicolon-, or newline-separated recipient email addresses or glob patterns to skip. Matches are case-insensitive, so values like `partner@example.com` or `e2e-*` both work.
- `POLL_INTERVAL_SECONDS`: How often to poll Mailpit (default 10).
- `OTP_REGEX`: Regex used to extract the OTP (default `\b\d{6,8}\b`).
- `MAX_MESSAGES_PER_POLL`: Safety cap on how many messages are inspected per poll (default 20).
- `PROCESSED_DB_PATH`: Path to a sqlite DB storing processed Mailpit message IDs and heartbeat state (default `db/processed.sqlite`).
- `LOG_LEVEL`: Log level for the service (`panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace`; default `info`).
- `HEALTHZ_ADDR`: Address used by the HTTP health server. Default `:8080`.

### Heartbeat

All heartbeat settings are optional. The heartbeat flow only runs when `HEARTBEAT_ENABLED=true`.

- `HEARTBEAT_ENABLED`: Enables the SMTP -> Mailpit heartbeat flow.
- `HEARTBEAT_SMTP_HOST`: SMTP server host.
- `HEARTBEAT_SMTP_PORT`: SMTP server port. Default `587`.
- `HEARTBEAT_SMTP_USERNAME`: Optional SMTP username.
- `HEARTBEAT_SMTP_PASSWORD`: Optional SMTP password.
- `HEARTBEAT_SMTP_FROM_EMAIL`: Sender address used for the heartbeat email.
- `HEARTBEAT_RECIPIENT_EMAIL`: Mailpit inbox used for the probe. Defaults to `heartbeat@example.com`.
- `HEARTBEAT_SUBJECT_PREFIX`: Subject prefix used to identify heartbeat messages. Default `[mailpit2slack] heartbeat`.
- `HEARTBEAT_INTERVAL_MINUTES`: Interval between heartbeat cycles when there is no pending probe. Default `5`.
- `HEARTBEAT_WAIT_MINUTES`: How long to wait for each attempt before retrying. Defaults to `HEARTBEAT_INTERVAL_MINUTES`.
- `HEARTBEAT_MAX_ATTEMPTS`: Maximum number of send attempts before marking the service as `down`. Default `3`.

### Heartbeat state machine

- On first send, the service starts a heartbeat cycle and waits for the probe email.
- If the email is not found after the first timeout, it retries and persists `warning`.
- If the email is still not found after the second timeout, it retries again and remains `warning`.
- If the third attempt also does not arrive after the timeout window, it persists `down`.
- When the email arrives, the service deletes the heartbeat message from Mailpit and persists `up`.

The current heartbeat state is stored in the `heartbeat_state` table inside `PROCESSED_DB_PATH`, so retries and status survive restarts.

## Running locally

```bash
go run .
```

The process persists processed Mailpit message IDs in sqlite at `PROCESSED_DB_PATH`, so restarts won't re-send already seen messages. The default path lives under `./db`, which is mounted as a named volume in Docker Compose for persistence.

Ignored recipients are marked as processed, so they are skipped once and won't be re-evaluated on every poll.

Heartbeat messages are checked before OTP polling and deleted when found, so they do not pollute the OTP forwarding flow.

The service also exposes `GET /healthz`. It returns the persisted heartbeat state as JSON:

```json
{"status":"up","heartbeat_enabled":true,"attempts":0}
```

When heartbeat is disabled, `/healthz` returns `{"status":"disabled","heartbeat_enabled":false}`.
When heartbeat is `warning` or `down`, `/healthz` returns HTTP `503`.

## Docker

Build and run:

```bash
docker build -t mailpit2slack .
docker run --rm \
  -e MAILPIT_URL=https://mailpit.example.com \
  -e MAILPIT_USERNAME=your-username \
  -e MAILPIT_PASSWORD=your-password \
  -e MAILPIT_SEARCH_QUERY=mail.yourdomain.com \
  -e SLACK_WEBHOOK_URL=https://slack.example.invalid/webhook \
  -e HEARTBEAT_ENABLED=true \
  -e HEARTBEAT_SMTP_HOST=smtp.yourdomain.com \
  -e HEARTBEAT_SMTP_PORT=587 \
  -e HEARTBEAT_SMTP_USERNAME=your-user \
  -e HEARTBEAT_SMTP_PASSWORD=your-password \
  -e HEARTBEAT_SMTP_FROM_EMAIL=heartbeat@yourdomain.com \
  mailpit2slack
```

Adjust environment variables as needed.

### Docker Compose

1. Copy `.env.example` to `.env` and fill values.
2. Run:

```bash
docker compose up --build
```

The service uses `.env` via `env_file` in `docker-compose.yml`.
