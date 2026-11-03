# B1: per-identity SMB client container (SMBC-01). Idles until commands are exec'd.
FROM alpine:3.20
RUN apk add --no-cache samba-client bash coreutils
WORKDIR /staging
CMD ["sleep", "infinity"]
