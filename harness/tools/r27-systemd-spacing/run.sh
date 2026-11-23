#!/bin/sh
# r27-systemd-spacing — does systemd accept `ExecStartPost = …` / tab-spaced keys (no `ExecStartPost=` substring)? Needs sudo -n + systemd PID 1.
set -u
U=/etc/systemd/system/r27-sp.service; O=$(mktemp -u /tmp/r27-sp.XXXXXX)
printf '[Unit]\nDescription=r27 spacing probe\n[Service]\nType=oneshot\nExecStart=/bin/true\nExecStartPost = /bin/sh -c "echo spaced-post-ran > %s"\nExecStartPost\t=\t/bin/sh -c "echo tab-post-ran >> %s"\nRemainAfterExit=yes\n' "$O" "$O" | sudo -n tee $U >/dev/null
echo "unit has 'ExecStartPost=' substring: $(grep -c 'ExecStartPost=' $U)"
sudo -n systemctl daemon-reload && sudo -n systemctl start r27-sp.service
echo "ran: $(cat $O | tr '\n' ' ')"; systemctl --version | head -1
sudo -n systemctl stop r27-sp.service; sudo -n rm -f $U $O; sudo -n systemctl daemon-reload
