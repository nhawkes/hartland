#!/usr/bin/env bash
# Never prints a token: only claims, booleans and paths.
set -uo pipefail
out="$1"; mkdir -p "$out"
here="$(cd "$(dirname "$0")" && pwd)"
s() { echo "### $1" >> "$out/summary.md"; shift; { "$@"; echo "exit=$?"; } >> "$out/summary.md" 2>&1; echo >> "$out/summary.md"; }

s "host" sh -c 'uname -srm; nproc; free -g | head -2; df -h / | tail -1; grep PRETTY /etc/os-release; id'

# --- OIDC ---------------------------------------------------------------
python3 -m pip install -q --user 'pyjwt[crypto]==2.10.1' >/dev/null 2>&1 || echo "pip failed" >> "$out/summary.md"
aud="hartland-attest:sha256:$(printf 'hartland spike statement' | sha256sum | cut -d' ' -f1)"
enc="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$aud")"
token="$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$enc" | python3 -c 'import json,sys;print(json.load(sys.stdin)["value"])')"
printf '%s' "$token" | python3 "$here/verify.py" "$aud" > "$out/oidc.json" 2>&1
echo "exit=$?" >> "$out/oidc.json"

# --- Sandbox ------------------------------------------------------------
s "sysctl userns" sh -c 'sysctl kernel.apparmor_restrict_unprivileged_userns kernel.unprivileged_userns_clone user.max_user_namespaces 2>&1'
s "runner has sudo" sudo -n true
s "unprivileged unshare as runner" unshare --user --map-root-user --net --pid --fork --mount-proc true
leak='for f in /proc/[0-9]*/environ; do { tr "\0" "\n" < "$f"; } 2>/dev/null | grep -q "^ACTIONS_ID_TOKEN_REQUEST_TOKEN=" && echo "readable: $f"; done; echo scan-done'
s "token visible to runner uid (expected: yes)" sh -c "$leak"
sudo useradd -M -s /usr/sbin/nologin hlsandbox
s "token visible to sandbox uid (want: none)" sudo -u hlsandbox env -i sh -c "$leak"
s "sandbox uid has sudo (want: fail)" sudo -u hlsandbox env -i sudo -n true
s "sandbox uid unprivileged unshare" sudo -u hlsandbox env -i unshare --user --map-root-user --net --pid --fork --mount-proc true
s "network inside netns (want: fail)" sudo -u hlsandbox env -i unshare --user --map-root-user --net sh -c 'exec 3<>/dev/tcp/1.1.1.1/443 && echo connected'
s "network for sandbox uid without netns (info)" sudo -u hlsandbox env -i bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" && echo connected'
s "credential files readable by sandbox (want: none)" sudo -u hlsandbox env -i sh -c 'find /home /opt /etc -maxdepth 6 \( -name ".credentials*" -o -name ".runner" -o -name "*.pem" -o -name ".git-credentials" \) -readable 2>/dev/null | head -20; echo find-done'
s "runner home readable by sandbox (info)" sudo -u hlsandbox env -i sh -c 'ls -ld /home/runner /home/runner/work 2>&1; ls /home/runner 2>&1 | head'
sudo apt-get install -qy bubblewrap >/dev/null 2>&1
s "bwrap as sandbox uid" sudo -u hlsandbox env -i bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp /usr/bin/true

# --- Root-created namespaces, then drop to the sandbox uid -------------
jail() {
    sudo unshare --net --pid --mount --ipc --uts --fork --mount-proc \
        setpriv --reuid=hlsandbox --regid=hlsandbox --clear-groups \
        --no-new-privs --inh-caps=-all --bounding-set=-all \
        env -i PATH=/usr/bin:/bin "$@"
}
s "jail: identity and capabilities" jail sh -c 'id; grep -E "^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs)" /proc/self/status'
s "jail: network (want: fail)" jail bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" && echo connected || echo no-network'
s "jail: visible processes (want: only own)" jail sh -c 'ls /proc | grep -E "^[0-9]+$" | tr "\n" " "; echo'
s "jail: token scan (want: none)" jail sh -c "$leak"
s "jail: sudo (want: fail)" jail sudo -n true
s "jail: runner home (want: denied)" jail ls /home/runner
s "jail: launch overhead, 100 runs" bash -c 'start=$(date +%s%N); for i in $(seq 100); do sudo unshare --net --pid --mount --ipc --uts --fork --mount-proc setpriv --reuid=hlsandbox --regid=hlsandbox --clear-groups --no-new-privs --inh-caps=-all --bounding-set=-all /usr/bin/true; done; echo "$(( ($(date +%s%N) - start) / 100000000 ))ms per 100 / 100 = ms each x0.01 -> see raw"; echo "total_ns=$(( $(date +%s%N) - start ))"'

# --- Alternative: lift the AppArmor restriction, then bwrap as sandbox uid
sudo sysctl -q kernel.apparmor_restrict_unprivileged_userns=0
s "bwrap after sysctl, as sandbox uid" sudo -u hlsandbox env -i bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp /usr/bin/sh -c 'id; exec 3<>/dev/tcp/1.1.1.1/443 && echo connected || echo no-network'
exit 0
