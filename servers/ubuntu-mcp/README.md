# ubuntu-mcp

MCP server for administering **remote Ubuntu/Linux machines** over SSH from
Claude, Codex, Antigravity, or Kimi Work.
It supports several hosts and has 22 tools covering shell commands, files,
systemd, the journal, processes, apt, networking, disks, UFW, Docker and logins.

## Configuration

Normally managed by **MCP Vault** (template `ubuntu-mcp`): add Linux hosts in
the vault and tick them on the `ubuntu` server. The vault passes them as
`UBUNTU_MCP_HOSTS` at start, so no file with passwords is needed.

Without the vault, hosts can live in `hosts.json` next to this README (or the
file named by `UBUNTU_MCP_HOSTS_FILE`). The server re-reads that file whenever
it changes, so you don't need to restart after adding a host. Copy the shape
from `hosts.example.json`:

```json
{
  "hosts": [
    { "name": "vps1", "host": "203.0.113.10", "username": "ubuntu", "password": "..." }
  ]
}
```

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `name` | no | `host` | Name passed as `host=` to tools |
| `host` | yes | – | IP or hostname |
| `username` | yes | – | SSH user |
| `port` | no | 22 | |
| `password` | no* | – | *Needs `password`, `key_file`, or an agent/default key |
| `key_file` | no | – | Private key path (`~` allowed) |
| `sudo_password` | no | `password` | Used for `sudo -S` when the user isn't root |
| `readonly` | no | false | Blocks write tools and `sudo` in `ubuntu_run` |
| `description` | no | – | Shown by `ubuntu_list_hosts` |

Environment overrides:

- `UBUNTU_MCP_HOSTS`: inline JSON inventory, used instead of the file
- `UBUNTU_MCP_HOSTS_FILE`: path to the inventory file
- `UBUNTU_MCP_READONLY=true`: puts every host in read-only mode

## Tools

Every tool takes `host`. You can leave it out when only one host is configured.

Every tool carries MCP annotations (read-only / write / destructive). `ubuntu_run`,
`ubuntu_packages` (it can remove and purge), `ubuntu_kill_process` and
`ubuntu_reboot` are marked destructive; tools that mix reads and writes are
annotated for the strongest thing they can do. Refusals, unknown hosts and
connection failures come back as readable tool errors.

- `ubuntu_list_hosts`, `ubuntu_test_connection`
- `ubuntu_run`: runs any bash script, with optional `sudo`, `working_dir` and `timeout_sec`
- `ubuntu_system_info`, `ubuntu_disk_usage`, `ubuntu_network_info`
- `ubuntu_list_dir`, `ubuntu_read_file`, `ubuntu_write_file` (makes a `.bak` backup), `ubuntu_search_files`
- `ubuntu_upload_file`, `ubuntu_download_file` (SFTP)
- `ubuntu_services`, `ubuntu_service_control`, `ubuntu_journal`
- `ubuntu_processes`, `ubuntu_kill_process`
- `ubuntu_packages`: installed, search, show, upgradable, update, install, remove, purge, upgrade, autoremove
- `ubuntu_firewall_status`, `ubuntu_docker`, `ubuntu_logins`, `ubuntu_reboot` (needs `confirm=true`)

Some commands are always refused, even outside read-only mode: `rm -rf /`,
`mkfs`, `dd` writes to disk devices, `wipefs`, fork bombs, and recursive
chmod/chown of `/`.

## Notes

- Host keys are auto-accepted on first connect (paramiko `AutoAddPolicy`), the
  same as windows-mcp.
- Output is capped at 60k characters per stream.
- Commands run under `bash` with `LC_ALL=C.UTF-8` and
  `DEBIAN_FRONTEND=noninteractive`.
