#!/bin/bash
set -euo pipefail
# Executed inside the mailserver, preserving existing anti-spam/signing milters.
existing=$(postconf -h smtpd_milters)
case "$existing" in
  *inet:milter:9900*) ;;
  *) postconf -e "smtpd_milters = inet:milter:9900${existing:+, $existing}" ;;
esac
postconf -e "non_smtpd_milters = $(postconf -h smtpd_milters)"
postconf -e 'milter_protocol = 6'
postconf -e 'milter_default_action = quarantine'
postconf -e 'milter_connect_timeout = 5s'
postconf -e 'milter_command_timeout = 40s'
postconf -e 'milter_content_timeout = 40s'
