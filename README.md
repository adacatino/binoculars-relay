# Binoculars relay

Private Nostr relay for Property Management Binoculars.

- Members only: a key must be on the allowlist to connect (NIP-42 auth).
- Each member reads only events they wrote or events addressed to them (`p` tag).
- Records arrive already encrypted by the app; the relay never sees readable data.
- SQLite storage; replaceable/addressable events (NIP-01/33) and deletions (NIP-09).
- Caddy in front for automatic HTTPS.

## Install on a fresh Ubuntu server

Point a DNS A record (e.g. `relay.yourdomain.com`) at the server, then as root:

```
curl -fsSL https://raw.githubusercontent.com/adacatino/binoculars-relay/main/install.sh | bash -s relay.yourdomain.com
```

## Day-to-day

- Add a member: `binoculars-allow npub1...`
- Update the relay: `binoculars-update`
- Logs: `cd /opt/binoculars && docker compose logs -f relay`
- Data lives in `/opt/binoculars/data` (covered by the server's automatic backups).

## Local test

```
npm install
PORT=7777 DATA_DIR=./data node relay.mjs
```
