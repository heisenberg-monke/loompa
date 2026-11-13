# loompa

`loompa` is a Linux command-line tool for inspecting local accounts, configured privilege access, and system activity. It reads account and group information from the system, and uses files under `/var/log`, `/proc`, and `/etc` where relevant. Output is printed as tables.

## Build

Requirements:

- Linux
- CMake 3.30 or newer
- A C++23 compiler with `<format>` support

Build with:

```sh
cmake -S . -B build
cmake --build build
```

The executable is `build/loompa`. The build uses the CMake source directory as the project root; privilege snapshots and change history are written to `data/privileges.snapshot` and `data/privileges.changes` beneath that directory.

## Usage

```text
loompa [GLOBAL OPTION]... <COMMAND> [ARGS]
```

Global options:

| Option | Description |
| --- | --- |
| `-h`, `--help` | Show command help |
| `-V`, `--version` | Show version |
| `-v`, `--verbose` | Enable informational logging |
| `-q`, `--quiet` | Disable informational logging |

### Users and groups

```sh
loompa users list
loompa users show <username>
loompa users groups <group>
loompa users sessions
```

`users list` shows usernames, IDs, home directories, and shells. `users show` includes account details and group membership. `users groups` lists group members, including users whose primary group is the requested group. `users sessions` reports active utmpx sessions.

### Privileges

```sh
loompa privileges list
loompa privileges check <username>
loompa privileges changes [--since TIME] [--severity LEVEL]
```

Privilege inspection collects membership in the `sudo`, `wheel`, and `admin` groups, rules found in `/etc/sudoers` and non-hidden regular files in `/etc/sudoers.d`, and file capabilities reported by `getcap` in selected executable and security-helper directories. `check` evaluates the detected configuration for a user; it is an inspection aid and does not replace `sudo`'s own policy evaluation.

The first privilege command creates an initial snapshot. Later runs compare the current scan with that snapshot and append additions and removals to the change history. New additions are recorded as `HIGH`, removals as `MEDIUM`. The `--severity` filter accepts `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

### Activity

```sh
loompa activity status
loompa activity logins [--since DATE] [--until DATE] [--limit COUNT] [--user USER]
loompa activity failed-logins [--since DATE] [--until DATE] [--limit COUNT] [--user USER]
loompa activity sudo [--since DATE] [--until DATE] [--limit COUNT] [--user USER]
loompa activity processes [--limit COUNT] [--user USER]
```

`status` reports active sessions, process count, and availability of common login and authentication log sources. Login history is read from `/var/log/wtmp`; failed authentication events can be collected from `/var/log/btmp`, common authentication and audit logs, and the system journal when available. Sudo activity is collected from common authentication logs and journal entries. Process details come from `/proc`.

Activity sources vary by Linux distribution and may require elevated read permissions. Unavailable or unreadable sources can result in incomplete event listings. `--user` filters event or process results where supported; `--limit` caps the number of displayed rows.

`DATE` accepts GNU date expressions, for example `2026-10-25`, `yesterday`, `24 hours ago`, or `24h`. Quote expressions containing spaces so the shell passes them as one argument:

```sh
loompa activity logins --since '24 hours ago' --limit 20
loompa activity failed-logins --since yesterday --user alice
loompa activity sudo --since '2026-10-25 09:00' --until '2026-10-25 18:00'
```

## License

See [LICENSE](LICENSE).
