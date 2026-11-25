# local-priv-workshop

Deliberately vulnerable hosts for practising local privilege escalation, plus a
read-only auditor that finds the vectors you planted (or missed).

Everything here is for **authorised lab use only** — a throwaway VM, a snapshot
taken first. Running the builders on a machine you care about is how you lose it.

```
winpriv.bat                Windows lab builder   (run elevated, in a VM)
linux_priv_workshop.sh     Linux lab builder     (root, in a VM)
linux_local_privesc.sh     Linux auditor         (read-only, no root needed)
build/lint_bat.py          static checks for winpriv.bat (parse only)
```

---

## winpriv.bat

Anonymous workshop harness. Usage:

```
winpriv.bat              build the lab
winpriv.bat /noverify    skip the embedded-payload hash gate
winpriv.bat /undo        remove everything the script created
winpriv.bat /?           help
```

Creates `labuser` (password4321) and `labadmin` (password123). Dedicated names,
so an existing `user` or `admin` account on the box is never touched.

### Vectors

| # | Vector | Where to look |
|---|--------|---------------|
| 1 | DLL hijacking through a service PATH entry | `dllsvc`, `C:\Temp` |
| 2 | Weak service DACL, reconfigurable binPath | `daclsvc` |
| 3 | Unquoted service path | `unquotedsvc` |
| 4 | Weak permissions on a service's registry key | `regsvc` |
| 5 | Service binary writable by Users | `filepermsvc` |
| 6 | Autorun registry key | `HKLM\...\CurrentVersion\Run` |
| 7 | AlwaysInstallElevated (HKLM + HKCU) | MSI policy |
| 8 | Autologon password in Winlogon | `DefaultPassword` |
| 9 | Answer file with credentials | `C:\Windows\Panther`, `System32\Sysprep` |
| 10 | SYSTEM scheduled task on a writable script | `CleanUp` -> `C:\DevTools` |
| 11 | Writable Startup folder | `ProgramData\...\Startup` |
| 12 | On-logon SYSTEM task + `savecred` task | `LPE`, `SaveCred` |
| 13 | **Backup Operators membership** (SeBackupPrivilege) | log off/on, then `reg save hklm\sam` |
| 14 | **UAC bypass via fodhelper** (auto-elevating binary) | as `labadmin`: run `fodhelper.exe` |
| 15 | **Credentials on disk** | `Documents\deploy-notes.txt`, PSReadLine history, `.ssh\id_rsa`, `.git-credentials` |

`/verify` output (printed at the end) checks each one and reports pass/fail, so a
half-built lab is obvious instead of mysterious.

### What changed from the original, and why

- **Authorship and links removed.** No names, no external URLs; the banner is
  now just the workshop title.
- **Password mismatch fixed.** The banner advertised `password4321` while the
  code set `password321`. Both now agree with the banner.
- **Accounts renamed** to `labuser` / `labadmin` and guarded, so an existing
  `user`/`admin` on the machine is never given a lab password.
- **`setx /m Path` replaced.** `setx` truncates at 1024 characters and copies
  the *caller's user* PATH into the machine-wide value. The new
  `:append_system_path` reads the registry value and appends, idempotently, and
  `:remove_system_path` takes it back out on `/undo`.
- **Elevation check made locale-independent.** `net session` and
  `fsutil dirty query` are tried first; the original `whoami` string match only
  survives as a last resort, and it now checks the `S-1-16-12288` SID.
- **`/undo` added** — services, tasks, registry keys, accounts, folders,
  firewall and Defender policy all restored.
- **`/noverify` added** so you can edit the script without tripping the
  embedded-payload MD5 gates.
- **End-of-run verification** so you know the lab is actually live.

The embedded hex payloads were not touched: `build/lint_bat.py` decodes each one
and checks it against the MD5 the script gates on. All seven still match.

---

## linux_local_privesc.sh

Read-only LinPEAS-class auditor. ~900 checks across twelve sections.

```
./linux_local_privesc.sh                 normal scan
./linux_local_privesc.sh --quick         targeted scans only, no full inventory
./linux_local_privesc.sh --full          cross filesystem boundaries
./linux_local_privesc.sh --no-net        no network probes
./linux_local_privesc.sh --probe-metadata  GET the cloud metadata endpoint
./linux_local_privesc.sh --json          also write findings.json
./linux_local_privesc.sh -o DIR          output directory
./linux_local_privesc.sh --selftest      assert the helpers, scan nothing
```

Sections: system & kernel, sudo, SUID/SGID, capabilities, cron/systemd/hooks,
PATH & groups, writable files, credentials & secrets, network & services,
containers, installed software, hardening gaps.

Reading the output:

- `[CRIT]` directly actionable as the current user
- `[WARN]` needs a human look
- `[ .. ]` context
- `[ ok ]` a check that passed

Design notes that matter if you edit it:

- **One filesystem walk.** `find / -printf` builds `fs.tsv`, and every
  permission question is an awk query over that index. The first draft ran five
  separate `find /` passes plus `getcap -r /` plus a recursive grep of `$HOME`,
  which is minutes of I/O on a real disk.
- **Counters are file-backed**, because most checks run inside pipelines and
  subshells where variable increments are lost.
- **Findings are sanitised at the emit boundary**, so a multi-line process
  command line cannot corrupt the findings file.
- **Severity is ownership-aware**: your own writable `~/.local/bin` is INFO, a
  root-owned directory writable by you is CRIT.
- Each section header prints `(+Ns)` so a slow section names itself.

`--selftest` asserts the helper contracts (version ordering, permission
comparison, record sanitisation, findings plumbing) and exits non-zero on
failure.

---

## linux_priv_workshop.sh

The Linux counterpart to `winpriv.bat`. Root required.

```
sudo ./linux_priv_workshop.sh              apply every scenario
sudo ./linux_priv_workshop.sh --list
sudo ./linux_priv_workshop.sh --only suid,cron
sudo ./linux_priv_workshop.sh --skip nfs,docker
sudo ./linux_priv_workshop.sh --dry-run    print actions, change nothing
sudo ./linux_priv_workshop.sh --verify     check each planted vector is live
sudo ./linux_priv_workshop.sh --undo       restore the machine
```

Scenarios: `suid`, `cron`, `wildcard`, `systemd`, `sudo`, `sudoenv`, `caps`,
`path`, `secrets`, `profile`, `logrotate`, `docker`, `nfs`, `motd`.

Every change is journalled in `/var/lib/lab-priv/journal.tsv` before it is made,
with a backup copy of anything modified. `--undo` replays the journal backwards:
created paths are deleted, modified files restored, accounts and group
memberships removed, firewall and PATH put back.

Lab account: `heyuser` / `password4321`.

---

## Suggested loop

1. Snapshot the VM.
2. Build the lab: `winpriv.bat` or `sudo ./linux_priv_workshop.sh`.
3. Verify: `/verify` or `--verify`.
4. Log in as the low-privilege account.
5. Audit: `./linux_local_privesc.sh` (or your usual Windows tooling).
6. Work the vector by hand. Write down the command that worked.
7. Tear down: `/undo` or `--undo`, then snapshot back.

## Known limitations

- `winpriv.bat` was validated statically here (labels, parenthesis balance,
  payload hashes). It has not been executed on Windows from this machine — test
  it in the VM and report what breaks.
- `linux_local_privesc.sh` is verified with `--selftest` and a full parse pass.
  The end-to-end scan has not been re-run since the single-walk refactor.
- CVE matching is version-based. Distro backports routinely make a version
  string misleading; treat those hits as leads, not conclusions.
- `cups`, `nfs` and `docker` scenarios skip themselves when the host lacks the
  feature, and `--verify` reports them as failed rather than silently missing.

## Verifying a script without running its work

```bash
bash -n < linux_local_privesc.sh     # parse only
./linux_local_privesc.sh --selftest  # assert the helper contracts
sudo ./linux_priv_workshop.sh --dry-run
python3 build/lint_bat.py winpriv.bat
```

`lint_bat.py` checks label targets, parenthesis balance and `::` inside blocks,
then decodes every embedded hex payload and compares its MD5 against the hash
the script gates on. That is how the payloads were confirmed intact during the
refactor.

## Licence and provenance

MIT — see `LICENSE`. Use it, fork it, teach with it.

The embedded service binaries in `winpriv.bat` originate from a workshop that
has circulated publicly for years; the original authorship and licence are not
stated anywhere in the material. They are included unmodified, as the script's
own MD5 gates require. If you are a rights holder and want that changed, open an
issue and it will be replaced with a purpose-built payload.

## Contributing

The most useful contribution right now is a bug report from a real run: which
vector, which Windows build, what the console said. `winpriv.bat /verify` and
`linux_local_privesc.sh --selftest` exist so that a report can be specific.
