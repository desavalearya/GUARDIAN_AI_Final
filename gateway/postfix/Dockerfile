FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    postfix \
    opendkim \
    opendkim-tools \
    opendmarc \
    libsasl2-modules \
    ca-certificates \
    openssl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY gateway/postfix/main.cf /etc/postfix/main.cf
COPY gateway/postfix/master.cf /etc/postfix/master.cf
COPY gateway/postfix/opendkim.conf /etc/opendkim.conf
COPY gateway/postfix/opendmarc.conf /etc/opendmarc.conf
COPY gateway/postfix/sasl_passwd.template /etc/postfix/sasl_passwd.template
COPY gateway/postfix/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh \
    && mkdir -p /etc/opendkim/keys /var/spool/postfix/opendkim /var/spool/postfix/opendmarc \
    && chown -R opendkim:opendkim /etc/opendkim /var/spool/postfix/opendkim \
    && chown -R opendmarc:opendmarc /var/spool/postfix/opendmarc

EXPOSE 25 587

CMD ["/entrypoint.sh"]
