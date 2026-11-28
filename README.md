# CyberPatriot Guided Audit

`Goon.sh` is a Debian-focused system audit helper. It reports accounts,
services, permissions, package verification differences, selected kernel
settings, and other items to compare with the current challenge instructions.
Its findings are prompts for review, not proof that a setting is scored or
incorrect.

## Run

```bash
bash Goon.sh
sudo bash Goon.sh --audit
sudo bash Goon.sh --recommend
sudo bash Goon.sh --remediate
```

The default and `--audit` modes are read-only. `--recommend` also makes no
changes; it prints the same audit findings and suggested actions. Running with
`sudo` gives the audit more complete access.

Every run saves a timestamped report under `/root` when run as root, or under
the current user's home directory otherwise. If that location is not writable,
the report is saved under `/tmp`.

## Interactive remediation

`--remediate` requires root and an interactive terminal. After the audit, it
offers these optional actions, each requiring an explicit `yes` confirmation:

- Set `/etc/shadow` permissions to `640`, only when its owner/group is
  `root:shadow` and the current permissions are too broad.
- Set `kernel.kptr_restrict=1` for the current session, with an optional
  persistent setting.
- Set `net.ipv4.tcp_syncookies=1` for the current session, with an optional
  persistent setting.

Persistent kernel settings are written to
`/etc/sysctl.d/99-cyberpatriot-guided.conf`. Existing files not created by
this script are never overwritten. Before updating its own existing drop-in,
the script creates a metadata-preserving backup under
`/root/cyberpatriot-backups/`.

LightDM configuration is only displayed for inspection; the script never edits
it. It does not install or remove packages, disable services, delete accounts
or files, or decide which settings satisfy the challenge. Review every proposed
change against the challenge requirements before confirming it.