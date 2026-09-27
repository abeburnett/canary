# Clean-Mac lifecycle test

Runs SkillCanary the way a new customer would, in a disposable macOS VM
(Tart, the Cirrus Labs `macos-tahoe-vanilla` image, which has no developer
tools preinstalled). It never touches the host's policy folders.

    e2e/run.sh <path-to-canary-source>

`run.sh` clones the image, boots it headless, installs Apple's command-line
tools, tries the Homebrew path (`brew tap`, `brew trust`, `brew install
skillcanary`), copies the source in, and runs `lifecycle.py`: Scan, Guard, a
real `canary add` from GitHub, Lockdown, and back to Scan (25 checks).

Stand-ins, because nobody is at the VM's screen: `sudo` replaces the macOS
administrator dialog and the approval dialog is answered in code. The login
is the image's published default (`admin`/`admin`).

Last result: 25/25 on 2026-09-27 against v0.1.0.
