#!/usr/bin/env bash
# Installs the Binoculars private relay on a fresh Ubuntu server.
# Usage: curl -fsSL https://raw.githubusercontent.com/adacatino/binoculars-relay/main/install.sh | bash -s relay.yourdomain.com
set -euo pipefail
DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then echo "Usage: install.sh relay.yourdomain.com"; exit 1; fi
if [ "$(id -u)" -ne 0 ]; then echo "Please run as root (or with sudo)."; exit 1; fi

echo "==> Installing Docker and firewall"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io git ufw
apt-get install -y docker-compose-v2 || apt-get install -y docker-compose-plugin || true
systemctl enable --now docker

echo "==> Opening ports 22, 80, 443"
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

echo "==> Downloading the relay"
if [ -d /opt/binoculars/.git ]; then
  git -C /opt/binoculars pull --ff-only
else
  git clone --depth 1 https://github.com/adacatino/binoculars-relay /opt/binoculars
fi
cd /opt/binoculars
echo "DOMAIN=$DOMAIN" > .env
mkdir -p data
[ -f data/allowlist.txt ] || printf '# One npub per line. Changes apply within seconds.\n' > data/allowlist.txt

echo "==> Installing helper commands"
cat > /usr/local/bin/binoculars-allow <<'CMD'
#!/usr/bin/env bash
# Add a member: binoculars-allow npub1...
set -e
[ -n "${1:-}" ] || { echo "Usage: binoculars-allow npub1..."; exit 1; }
echo "$1  # added $(date +%F)" >> /opt/binoculars/data/allowlist.txt
echo "Added. Members now:"; grep -v '^#' /opt/binoculars/data/allowlist.txt
CMD
cat > /usr/local/bin/binoculars-update <<'CMD'
#!/usr/bin/env bash
set -e
cd /opt/binoculars && git pull --ff-only && docker compose up -d --build
CMD
chmod +x /usr/local/bin/binoculars-allow /usr/local/bin/binoculars-update

echo "==> Starting the relay (first start takes a few minutes)"
docker compose up -d --build

echo
echo "Done. Your relay address is: wss://$DOMAIN"
echo "Next: add your public ID (npub, from the app's Account screen) with:"
echo "  binoculars-allow npub1..."
