#!/bin/bash
# Run the SkillCanary lifecycle test in a fresh clone of the vanilla macOS VM.
# Usage: run.sh <path-to-canary-checkout>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$1
VM=skillcanary-e2e
IMAGE=ghcr.io/cirruslabs/macos-tahoe-vanilla:latest
KEY="$HERE/id_vm"
ASK="$HERE/askpass.sh"
step() { printf '\n== %s (%s)\n' "$1" "$(date +%H:%M:%S)"; }

[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY"
printf '#!/bin/sh\necho admin\n' > "$ASK"; chmod 700 "$ASK"

step "clone"
tart delete "$VM" 2>/dev/null || true
tart clone "$IMAGE" "$VM"
step "boot headless"
nohup tart run --no-graphics "$VM" > "$HERE/vm-run.log" 2>&1 & disown
IP=$(tart ip --wait 300 "$VM")
echo "ip $IP"

SSHOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
for i in $(seq 1 60); do
  SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force ssh "${SSHOPT[@]}" admin@"$IP" true 2>/dev/null && break
  sleep 5
done
step "install throwaway key"
SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force ssh "${SSHOPT[@]}" admin@"$IP" \
  "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys" < "$KEY.pub"
S() { ssh "${SSHOPT[@]}" -i "$KEY" admin@"$IP" "$@"; }

step "fresh-Mac check: does /usr/bin/python3 run before developer tools?"
S '/usr/bin/python3 -c "print(\"python ok\")" 2>&1 | head -3; echo "exit ${PIPESTATUS[0]}"' || true

step "install command-line tools headlessly"
S 'touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress;
   P=$(softwareupdate -l 2>/dev/null | grep -E "\* Label: Command Line Tools" | tail -1 | sed "s/^.*Label: //");
   echo "installing: $P";
   for try in 1 2 3; do echo admin | sudo -S softwareupdate -i "$P" 2>&1 | tail -2; xcode-select -p >/dev/null 2>&1 && break; echo "retry $try"; done;
   /usr/bin/python3 --version'

step "customer path: Homebrew install of skillcanary"
S 'echo admin | sudo -S -v 2>/dev/null; NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" >/tmp/brew-install.log 2>&1; echo "homebrew install exit $?";
   eval "$(/opt/homebrew/bin/brew shellenv)";
   brew tap abeburnett/tap && brew trust abeburnett/tap && brew install skillcanary 2>&1 | tail -3;
   echo "--- canary --help"; canary --help | head -2;
   echo "--- canary setup --level scan"; canary setup --level scan; echo "exit $?";
   echo "--- canary doctor"; canary doctor; echo "exit $?";
   mkdir -p /tmp/s && printf -- "---\nname: s\ndescription: d\n---\nUse bullets.\n" > /tmp/s/SKILL.md;
   echo "--- canary check (no classifier in the VM)"; canary check /tmp/s --text | head -3; echo "exit $?"' || true

step "copy the product"
tar -C "$SRC" -czf - LICENSE bin canary | S 'mkdir -p ~/canary-kit && tar -xzf - -C ~/canary-kit'
scp "${SSHOPT[@]}" -i "$KEY" "$HERE/lifecycle.py" admin@"$IP":~/lifecycle.py

step "lifecycle"
set +e
S '/usr/bin/python3 -B ~/lifecycle.py'
RESULT=$?
set -e

step "stop"
tart stop "$VM" || true
echo "lifecycle exit $RESULT"
exit $RESULT
