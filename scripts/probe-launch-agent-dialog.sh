#!/bin/zsh
# Probe for the front-door watcher (slice B2): can a launch agent show a
# SkillCanary-style dialog, and does launchd restart it after it is killed?
#
# Run it in your own terminal. It installs a throwaway launch agent
# (com.skillcanary.probe), waits for you to answer one dialog, kills the
# agent once to see whether launchd restarts it, then removes everything.
# Nothing else on the Mac is changed.
set -u
LABEL=com.skillcanary.probe
PLIST=~/Library/LaunchAgents/$LABEL.plist
WORK=$(mktemp -d /tmp/canary-launch-probe-XXXX)
DOMAIN=gui/$(id -u)

cat > $WORK/agent.sh <<'SH'
#!/bin/zsh
# Each start leaves a line, then the first start shows one dialog.
print "started $(date +%s)" >> "$1/starts.log"
if [[ ! -e "$1/asked" ]]; then
  touch "$1/asked"
  answer=$(/usr/bin/osascript -e 'display dialog "SkillCanary launch-agent probe: can you see this? Click Yes." with title "SkillCanary" buttons {"No", "Yes"} default button "Yes" giving up after 120' 2>&1)
  print "dialog: $answer" >> "$1/starts.log"
fi
sleep 600
SH
chmod +x $WORK/agent.sh

mkdir -p ~/Library/LaunchAgents
cat > $PLIST <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/bin/zsh</string><string>$WORK/agent.sh</string><string>$WORK</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict></plist>
XML

launchctl bootstrap $DOMAIN $PLIST && print "Loaded. A dialog should appear now; answer it."
for i in {1..130}; do grep -q '^dialog:' $WORK/starts.log 2>/dev/null && break; sleep 1; done
print -r -- "-- first start:"; cat $WORK/starts.log
launchctl kill SIGKILL $DOMAIN/$LABEL
sleep 15
print -r -- "-- after one kill (a second 'started' line means launchd restarted it):"; cat $WORK/starts.log
launchctl bootout $DOMAIN/$LABEL 2>/dev/null
rm -f $PLIST
rm -rf $WORK
print "Removed the probe agent."
