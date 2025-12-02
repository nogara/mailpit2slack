# Mailpit to Slack OTP Forwarder

A small Go service that polls a Mailpit instance for OTP emails and forwards the extracted code and recipient to a Slack channel via an incoming webhook.

## Configuration

Copy `.env.example` to `.env` (or set the variables directly):

- `MAILPIT_URL` (required): Base URL of the Mailpit server.
- `MAILPIT_USERNAME` / `MAILPIT_PASSWORD`: Optional basic auth credentials.
- `MAILPIT_SEARCH_QUERY`: String passed to Mailpit `/api/v1/search` to scope messages (e.g., recipient email or domain). Falls back to `TEST_EMAIL_DOMAIN`.
- `SLACK_WEBHOOK_URL` (required): Slack incoming webhook URL.
- `POLL_INTERVAL_SECONDS`: How often to poll Mailpit (default 10).
- `OTP_REGEX`: Regex used to extract the OTP (default `\b\d{6,8}\b`).
- `MAX_MESSAGES_PER_POLL`: Safety cap on how many messages are inspected per poll (default 20).
- `PROCESSED_DB_PATH`: Path to a sqlite DB storing processed Mailpit message IDs to avoid duplicate Slack posts (default `db/processed.sqlite`).

## Running locally

```bash
go run main.go
```

The process persists processed Mailpit message IDs in sqlite at `PROCESSED_DB_PATH`, so restarts won't re-send already seen messages. The default path lives under `./db`, which is mounted as a named volume in Docker Compose for persistence.

## Docker

Build and run:

```bash
docker build -t mailpit2slack .
docker run --rm \
  -e MAILPIT_URL=https://mailpit.s.litmetrix.io \
  -e MAILPIT_USERNAME=your-username \
  -e MAILPIT_PASSWORD=your-password \
  -e MAILPIT_SEARCH_QUERY=mail.yourdomain.com \
  -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ \
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
