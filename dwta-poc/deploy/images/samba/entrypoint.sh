#!/usr/bin/env bash
# SMBS-02: create groups and users idempotently, then run smbd in the foreground.
# SMB_IDENTITIES = "name:group1,group2;name2:group1"  passwords in SMB_PW_<NAME> (upper-case, '-' -> '_')
set -euo pipefail

: "${SMB_IDENTITIES:?SMB_IDENTITIES is required}"
mkdir -p /srv/shares/finance /srv/shares/software /var/log/samba
chmod 0777 /srv/shares/finance /srv/shares/software

IFS=';' read -ra ENTRIES <<< "$SMB_IDENTITIES"
for entry in "${ENTRIES[@]}"; do
  name="${entry%%:*}"; groups="${entry#*:}"
  IFS=',' read -ra GROUPS_ARR <<< "$groups"
  for g in "${GROUPS_ARR[@]}"; do getent group "$g" >/dev/null || groupadd "$g"; done
  id "$name" >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin -G "$groups" "$name"
  var="SMB_PW_$(echo "$name" | tr 'a-z-' 'A-Z_')"
  pw="$(printenv "$var" || true)"
  [ -n "$pw" ] || { echo "missing $var" >&2; exit 1; }
  printf '%s\n%s\n' "$pw" "$pw" | smbpasswd -s -a "$name" >/dev/null
  smbpasswd -e "$name" >/dev/null
done

cp /etc/samba/smb.conf.tmpl /etc/samba/smb.conf
testparm -s /etc/samba/smb.conf >/dev/null 2>&1 || { testparm -s /etc/samba/smb.conf; exit 1; }
touch /var/log/samba/audit.log
exec smbd --foreground --no-process-group
