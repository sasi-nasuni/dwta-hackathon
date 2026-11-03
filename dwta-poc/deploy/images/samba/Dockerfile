# B2: Samba share with vfs_full_audit (SMBS-01)
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-vfs-modules smbclient tini \
 && rm -rf /var/lib/apt/lists/*
COPY smb.conf.tmpl /etc/samba/smb.conf.tmpl
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 445
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD bash -c '</dev/tcp/127.0.0.1/445' || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
