#!/bin/bash
set -euo pipefail

DOMAIN="${MAIL_DOMAIN:-example.com}"
HOSTNAME="${MAIL_HOSTNAME:-mail.${DOMAIN}}"
SELECTOR="${DKIM_SELECTOR:-guardian}"
RELAYHOST="${RELAYHOST:-}"
RELAY_USER="${RELAY_USER:-}"
RELAY_PASSWORD="${RELAY_PASSWORD:-}"
DEMO_RECEIVER_DOMAIN="${DEMO_RECEIVER_DOMAIN:-company-b.test}"
DEMO_RECEIVER_HOST="${DEMO_RECEIVER_HOST:-receiver}"
DEMO_RECEIVER_PORT="${DEMO_RECEIVER_PORT:-1025}"

# TLS snakeoil if missing
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
  apt-get update && apt-get install -y --no-install-recommends ssl-cert && rm -rf /var/lib/apt/lists/*
fi

postconf -e "myhostname = ${HOSTNAME}"
postconf -e "mydomain = ${DOMAIN}"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = localhost, localhost.localdomain, ${HOSTNAME}, ${DOMAIN}"
postconf -e "home_mailbox = Maildir/"
postconf -e "milter_default_action = accept"
postconf -e "maillog_file = /dev/stdout"

if [ -n "$RELAYHOST" ]; then
  postconf -e "relayhost = ${RELAYHOST}"
  if [ -n "$RELAY_USER" ] && [ -n "$RELAY_PASSWORD" ]; then
    echo "${RELAYHOST} ${RELAY_USER}:${RELAY_PASSWORD}" > /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_tls_security_level = encrypt"
  fi
else
  postconf -e "relayhost ="
fi

# Route the demo organisation's domain through PhishProof to its downstream SMTP server.
# This preserves the normal relayhost behavior for every other domain.
if [ -n "${DEMO_RECEIVER_DOMAIN}" ] && [ -n "${DEMO_RECEIVER_HOST}" ]; then
  echo "${DEMO_RECEIVER_DOMAIN} smtp:[${DEMO_RECEIVER_HOST}]:${DEMO_RECEIVER_PORT}" > /etc/postfix/transport
  postmap /etc/postfix/transport
  postconf -e "transport_maps = hash:/etc/postfix/transport"
fi

# Virtual aliases so local domain recipients land on catchall user
cat > /etc/postfix/virtual <<EOF
@${DOMAIN} catchall
user@${DOMAIN} catchall
analyst@${DOMAIN} catchall
EOF
postmap /etc/postfix/virtual
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"

# Catch-all local user (webmail uses Postgres; Maildir is local backup)
id catchall 2>/dev/null || useradd -m -u 5000 -s /usr/sbin/nologin catchall || true
mkdir -p /home/catchall/Maildir/{cur,new,tmp}
chown -R catchall:catchall /home/catchall
chmod -R 700 /home/catchall/Maildir

printf 'catchall: catchall\n' > /etc/aliases
newaliases
postconf -e "alias_maps = hash:/etc/aliases"
postconf -e "alias_database = hash:/etc/aliases"

# OpenDKIM keys
mkdir -p "/etc/opendkim/keys/${DOMAIN}" /var/run/opendkim /var/run/opendmarc
chown opendkim:opendkim /var/run/opendkim
chown opendmarc:opendmarc /var/run/opendmarc
if [ ! -f "/etc/opendkim/keys/${DOMAIN}/${SELECTOR}.private" ]; then
  opendkim-genkey -b 2048 -d "${DOMAIN}" -D "/etc/opendkim/keys/${DOMAIN}" -s "${SELECTOR}" -v
fi
chown -R opendkim:opendkim /etc/opendkim
chmod 600 "/etc/opendkim/keys/${DOMAIN}/${SELECTOR}.private" || true

cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
*.${DOMAIN}
172.16.0.0/12
10.0.0.0/8
192.168.0.0/16
EOF

echo "${SELECTOR}._domainkey.${DOMAIN} ${DOMAIN}:${SELECTOR}:/etc/opendkim/keys/${DOMAIN}/${SELECTOR}.private" > /etc/opendkim/KeyTable
echo "*@${DOMAIN} ${SELECTOR}._domainkey.${DOMAIN}" > /etc/opendkim/SigningTable

sed -i "s|^AuthservID .*|AuthservID ${HOSTNAME}|" /etc/opendmarc.conf
sed -i "s|^TrustedAuthservIDs .*|TrustedAuthservIDs ${HOSTNAME}|" /etc/opendmarc.conf

if [ -f "/etc/opendkim/keys/${DOMAIN}/${SELECTOR}.txt" ]; then
  echo "======== DKIM DNS RECORD (add this TXT) ========"
  cat "/etc/opendkim/keys/${DOMAIN}/${SELECTOR}.txt"
  echo "======== SPF example: v=spf1 mx a ip4:YOUR.PUBLIC.IP ~all ========"
  echo "======== DMARC example: v=DMARC1; p=none; rua=mailto:dmarc@${DOMAIN} ========"
fi

MILTERS="inet:milter:8891"
if opendkim -x /etc/opendkim.conf; then
  MILTERS="${MILTERS},inet:localhost:8892"
  echo "OpenDKIM started"
else
  echo "WARN: OpenDKIM failed to start; continuing with Guardian milter only"
fi
if opendmarc -c /etc/opendmarc.conf; then
  MILTERS="${MILTERS},inet:localhost:8893"
  echo "OpenDMARC started"
else
  echo "WARN: OpenDMARC failed to start; continuing without it"
fi

postconf -e "smtpd_milters = ${MILTERS}"
postconf -e "non_smtpd_milters = ${MILTERS}"

echo "Waiting for Guardian milter..."
for i in $(seq 1 60); do
  if nc -z milter 8891; then
    echo "Milter is up"
    break
  fi
  sleep 1
done

exec /usr/sbin/postfix start-fg
