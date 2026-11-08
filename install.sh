#!/bin/bash
set -euo pipefail

if [ "$#" -ne 2 ] || [ "$(id -u)" -ne 0 ]; then
    echo "Uso: sudo bash install.sh USUARIO IP_DO_KALI" >&2
    exit 2
fi
user=$1
bind=$2
[[ $user =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "Usuário inválido" >&2; exit 2; }
[[ $bind =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "IP inválido" >&2; exit 2; }
getent passwd "$user" >/dev/null || { echo "Usuário inexistente" >&2; exit 2; }
ip -4 -o addr show | grep -F " $bind/" >/dev/null || { echo "Configure o IP no Kali antes de instalar" >&2; exit 2; }
for program in sshd script openssl python3 systemctl; do command -v "$program" >/dev/null || { echo "Falta: $program" >&2; exit 2; }; done

src=$(cd -- "$(dirname -- "$0")" && pwd)
home=$(getent passwd "$user" | cut -d: -f6)
root="$home/ssh-audit"
install -d -o "$user" -g "$(id -gn "$user")" -m 700 "$root"
install -o root -g root -m 755 "$src/ssh-audit.py" /usr/local/bin/ssh-audit
install -o root -g root -m 755 "$src/ssh-audit-view.py" /usr/local/bin/ssh-audit-view

if [ ! -f "$root/.viewer-password" ]; then
    python3 - "$root/.viewer-password" <<'PY'
import pathlib, secrets, sys
path = pathlib.Path(sys.argv[1])
path.write_text(secrets.token_urlsafe(24))
path.chmod(0o600)
PY
fi
if [ ! -f "$root/.viewer-cert.pem" ] || [ ! -f "$root/.viewer-key.pem" ]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
        -keyout "$root/.viewer-key.pem" -out "$root/.viewer-cert.pem" \
        -subj "/CN=$bind" -addext "subjectAltName=IP:$bind" >/dev/null 2>&1
fi
chown "$user:$(id -gn "$user")" "$root"/.viewer-*
chmod 600 "$root"/.viewer-*

cat > /etc/systemd/system/ssh-audit-view.service <<EOF
[Unit]
Description=Local SSH audit viewer
After=network.target

[Service]
Type=simple
User=$user
Environment=SSH_AUDIT_USER=$user
Environment=SSH_AUDIT_BIND=$bind
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-audit-view
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ssh-audit-view.service

marker="# ssh-audit managed rule"
if ! grep -Fqx "$marker" /etc/ssh/sshd_config; then
    cp -p /etc/ssh/sshd_config "/etc/ssh/sshd_config.pre-audit.$(date +%Y%m%d%H%M%S)"
    candidate=$(mktemp)
    cp /etc/ssh/sshd_config "$candidate"
    printf '\n%s\nMatch User %s\n    ForceCommand /usr/local/bin/ssh-audit\n' "$marker" "$user" >> "$candidate"
    sshd -t -f "$candidate"
    cat "$candidate" > /etc/ssh/sshd_config
    rm -f "$candidate"
    sshd -t
    systemctl reload ssh
fi

echo "Instalado: https://$bind:8765/ (usuário: $user)"
echo "Senha em $root/.viewer-password; leia-a localmente com sudo cat."
