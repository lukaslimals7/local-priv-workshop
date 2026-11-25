#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2086,SC2016,SC2129,SC1090
# =============================================================================
#  linux_priv_workshop.sh   v1.0.0
#  Builds a deliberately vulnerable Linux host so you can practise every
#  local-privilege-escalation primitive. The Linux counterpart to winpriv.bat.
#
#  EVERY SCENARIO IS A REAL MISCONFIGURATION. Run this only inside a throwaway
#  VM, snapshot it first, and never on anything you care about.
#
#  Usage:
#    sudo ./linux_priv_workshop.sh                 apply every scenario
#    sudo ./linux_priv_workshop.sh --list          show scenarios
#    sudo ./linux_priv_workshop.sh --only suid,cron
#    sudo ./linux_priv_workshop.sh --skip nfs,docker
#    sudo ./linux_priv_workshop.sh --dry-run       print actions, change nothing
#    sudo ./linux_priv_workshop.sh --verify        check the lab is actually set up
#    sudo ./linux_priv_workshop.sh --undo          restore the machine
#    sudo ./linux_priv_workshop.sh --yes           skip the confirmation prompt
#
#  Every change is journalled in /var/lib/lab-priv/. --undo replays that
#  journal backwards: created paths are deleted, modified files are restored
#  from the copies taken before the change, and the lab accounts are removed.
# =============================================================================

VERSION="1.0.0"
LAB_USER="heyuser"
LAB_PASS="password4321"
ROOT="/opt/lab-priv"
STATE="/var/lib/lab-priv"
JOURNAL="$STATE/journal.tsv"
BACKUPS="$STATE/backups"
DRY=0
ASSUME_YES=0
ONLY=""
SKIP=""
ACTION="apply"

RED=""; GRN=""; YEL=""; BLU=""; DIM=""; RST=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'
    BLU=$'\033[1;36m'; DIM=$'\033[2m'; RST=$'\033[0m'
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$GRN" "$RST" "$*"; }
act()  { printf '%s[ .. ]%s %s\n' "$BLU" "$RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%s[fail]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

SCENARIOS="suid cron wildcard systemd sudo sudoenv caps path secrets profile logrotate docker nfs motd"

while [ $# -gt 0 ]; do
    case "$1" in
        --undo)      ACTION="undo" ;;
        --verify)    ACTION="verify" ;;
        --list)      ACTION="list" ;;
        --dry-run)   DRY=1 ;;
        --yes|-y)    ASSUME_YES=1 ;;
        --only)      shift; ONLY="${1:-}" ;;
        --skip)      shift; SKIP="${1:-}" ;;
        -h|--help)   usage ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

if [ "$ACTION" = "list" ]; then
    cat <<'EOF'
scenarios:
  suid       setuid copies of GTFOBins interpreters (vim, find, bash, python3, tar, ...)
  cron       root cron job executing a world-writable script
  wildcard   root tar/rsync job with a shell wildcard in an attacker-writable cwd
  systemd    root systemd service running a writable script, unit file also writable
  sudo       NOPASSWD sudo rules for GTFOBins binaries, plus a wildcard rule
  sudoenv    sudoers env_keep of LD_PRELOAD/LD_LIBRARY_PATH
  caps       file capabilities: cap_setuid, cap_dac_read_search, cap_setfcap
  path       writable directory early in PATH used by a root-executed script
  secrets    plaintext credentials, world-readable SSH key, shell history, backups
  profile    writable /etc/profile.d script executed on root login
  logrotate  logrotate postrotate with a writable target directory
  docker     lab user in the docker group (host socket) - docker only
  nfs        /etc/exports with no_root_squash - needs nfs-kernel-server
  motd       dynamic MOTD script run by root on every SSH login
EOF
    exit 0
fi

[ "$(id -u)" = "0" ] || die "must run as root (use sudo)"

want() {
    local s="$1"
    case ",$SKIP," in *",$s,"*) return 1 ;; esac
    [ -z "$ONLY" ] && return 0
    case ",$ONLY," in *",$s,"*) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------- journaling
j_created() { printf 'CREATED\t%s\n' "$1" >> "$JOURNAL"; }
j_modified() {
    local f="$1" n
    [ -e "$f" ] || { j_created "$f"; return 0; }
    n=$(printf '%s' "$f" | tr '/' '_')
    mkdir -p "$BACKUPS"
    cp -a "$f" "$BACKUPS/$n" 2>/dev/null
    printf 'MODIFIED\t%s\t%s\n' "$f" "$BACKUPS/$n" >> "$JOURNAL"
}
j_note() { printf 'NOTE\t%s\n' "$1" >> "$JOURNAL"; }

# write text to a path, journalling it first
put() { # $1=path  $2=content  [$3=mode]
    local p="$1" c="$2" m="${3:-0644}"
    if [ "$DRY" = "1" ]; then act "would write $p ($m)"; return 0; fi
    j_modified "$p"
    mkdir -p "$(dirname "$p")"
    printf '%s\n' "$c" > "$p"
    chmod "$m" "$p"
}

# ---------------------------------------------------------------- scenarios
sc_suid() {
    act "setuid GTFOBins copies"
    local b
    for b in vim find bash less python3 tar base64 env awk; do
        local src; src=$(command -v "$b" 2>/dev/null) || continue
        local dst="$ROOT/bin/suid_$b"
        if [ "$DRY" = "1" ]; then act "would install $dst from $src (4755)"; continue; fi
        mkdir -p "$ROOT/bin"
        cp "$src" "$dst"
        chown root:root "$dst"
        chmod 4755 "$dst"
        j_created "$dst"
        ok "SUID: $dst"
    done
    # a straight copy of sh, the classic
    if [ "$DRY" = "0" ]; then
        cp /bin/bash "$ROOT/bin/suid_shell"; chown root:root "$ROOT/bin/suid_shell"
        chmod 4755 "$ROOT/bin/suid_shell"; j_created "$ROOT/bin/suid_shell"
        ok "SUID: $ROOT/bin/suid_shell  (./suid_shell -p)"
    fi
}

sc_cron() {
    act "root cron job on a world-writable script"
    put "$ROOT/scripts/cleanup.sh" '#!/bin/sh
# "log cleanup" - world writable, root cron runs it every minute
find /tmp -name "*.log" -mtime +7 -delete 2>/dev/null
' 0777
    put /etc/cron.d/lab-cleanup "* * * * * root $ROOT/scripts/cleanup.sh >/dev/null 2>&1" 0644
    [ "$DRY" = "0" ] && ok "cron: /etc/cron.d/lab-cleanup -> $ROOT/scripts/cleanup.sh (0777)"
}

sc_wildcard() {
    act "wildcard injection (tar *)"
    put "$ROOT/scripts/backup.sh" '#!/bin/sh
cd /var/lab-backup && tar czf /var/backups/lab.tar.gz *
' 0755
    put /etc/cron.d/lab-backup "*/2 * * * * root $ROOT/scripts/backup.sh >/dev/null 2>&1" 0644
    if [ "$DRY" = "0" ]; then
        mkdir -p /var/lab-backup && chmod 0777 /var/lab-backup
        j_created /var/lab-backup
        ok "wildcard: /var/lab-backup is 0777, root runs 'tar czf ... *' from it"
        ok "  exploit: touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'"
    fi
}

sc_systemd() {
    act "root systemd service running a writable script"
    put "$ROOT/app/run.sh" '#!/bin/sh
# long-running "app"
while true; do sleep 30; done
' 0777
    put /etc/systemd/system/labapp.service '[Unit]
Description=Lab App
[Service]
Type=simple
ExecStart=/opt/lab-priv/app/run.sh
Restart=always
User=root
[Install]
WantedBy=multi-user.target' 0666
    if [ "$DRY" = "0" ]; then
        chmod 0666 /etc/systemd/system/labapp.service
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable --now labapp.service >/dev/null 2>&1
        j_created /etc/systemd/system/multi-user.target.wants/labapp.service
        ok "systemd: labapp.service runs $ROOT/app/run.sh as root (both writable)"
    fi
}

# Install a sudoers fragment only if it parses.
# A single unparseable file in /etc/sudoers.d disables sudo entirely -- including
# the sudo you would need in order to delete it ("no valid sudoers sources
# found"). Validate a temp file first, then move it into place atomically.
# The temp name starts with a dot: sudo ignores files containing a '.'.
put_sudoers() { # $1 = path, $2 = content
    local p="$1" c="$2" tmp out
    if [ "$DRY" = "1" ]; then act "would write $p"; return 0; fi
    tmp="$(dirname "$p")/.$(basename "$p").tmp"
    j_modified "$p"
    printf '%s\n' "$c" > "$tmp"
    chmod 0440 "$tmp"
    if ! out=$(visudo -cf "$tmp" 2>&1); then
        rm -f "$tmp"
        warn "REFUSED: generated sudoers fragment failed validation, $p not installed"
        printf '%s\n' "$out" | head -3
        return 1
    fi
    mv -f "$tmp" "$p"
    if ! visudo -c >/dev/null 2>&1; then
        rm -f "$p"
        warn "REFUSED: that fragment broke the global sudoers set, removed again"
        return 1
    fi
    ok "sudoers fragment installed: $p"
    return 0
}

sc_sudo() {
    act "NOPASSWD sudo for GTFOBins"
    local rules="" b
    # NOTE: a rule without a leading '%' applies to a USER; '%name' means GROUP.
    for b in vim less find awk rsync systemctl tar env; do
        command -v "$b" >/dev/null 2>&1 || continue
        rules="${rules}${LAB_USER} ALL=(root) NOPASSWD: $(command -v "$b")
"
    done
    [ -n "$rules" ] || { warn "none of the target binaries exist here, skipping"; return 0; }
    if put_sudoers /etc/sudoers.d/90-lab "$rules"; then
        [ "$DRY" = "0" ] && ok "sudo: $(printf '%s' "$rules" | grep -c NOPASSWD) NOPASSWD rules for $LAB_USER"
    fi
}

sc_sudoenv() {
    act "sudoers env_keep LD_PRELOAD"
    put_sudoers /etc/sudoers.d/91-labenv 'Defaults env_keep += "LD_PRELOAD LD_LIBRARY_PATH"'
}

sc_caps() {
    act "file capabilities"
    local p
    p=$(command -v python3 2>/dev/null) && [ -n "$p" ] && {
        if [ "$DRY" = "0" ]; then
            cp "$p" "$ROOT/bin/cap_python3"; chmod 0755 "$ROOT/bin/cap_python3"
            setcap cap_setuid+ep "$ROOT/bin/cap_python3"
            j_created "$ROOT/bin/cap_python3"
            ok "caps: $ROOT/bin/cap_python3 has cap_setuid (os.setuid(0))"
        fi
    }
    p=$(command -v tar 2>/dev/null) && {
        if [ "$DRY" = "0" ]; then
            mkdir -p "$ROOT/bin"
            cp "$p" "$ROOT/bin/cap_tar"; chmod 0755 "$ROOT/bin/cap_tar"
            setcap cap_dac_read_search+ep "$ROOT/bin/cap_tar"
            j_created "$ROOT/bin/cap_tar"
            ok "caps: $ROOT/bin/cap_tar has cap_dac_read_search (read /etc/shadow)"
        fi
    }
    [ "$DRY" = "1" ] && act "would setcap cap_setuid on a python3 copy"
}

sc_path() {
    act "writable PATH entry used by root"
    put /etc/profile.d/99-lab-path.sh "export PATH=$ROOT/bin:\$PATH" 0644
    put "$ROOT/bin/lab-root-task" '#!/bin/sh
# root task that calls an unqualified command
logger -t lab "task ran as $(id -un)"
' 0755
    put "$ROOT/scripts/root-task.sh" '#!/bin/sh
PATH=/opt/lab-priv/bin:$PATH
lab-root-task
' 0755
    put /etc/cron.d/lab-task "*/3 * * * * root $ROOT/scripts/root-task.sh" 0644
    if [ "$DRY" = "0" ]; then
        chmod 0777 "$ROOT/bin"
        ok "path: $ROOT/bin is 0777 and first in a root cron PATH"
    fi
}

sc_secrets() {
    act "planted credentials and keys"
    mkdir -p "$ROOT/backup" 2>/dev/null
    put "$ROOT/backup/credentials.txt" 'service=mysql
host=127.0.0.1
user=dbadmin
password=Summer2024!
' 0644
    put "$ROOT/backup/.env" 'DATABASE_URL=postgres://app:S3cretPass@127.0.0.1:5432/app
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
' 0644
    put /root/.lab_history 'mysql -u root -pS3cretRootPass
sshpass -p "labpass123" ssh deploy@10.0.0.5
export API_TOKEN=ghp_exampleTokenValue123
curl -u admin:admin http://127.0.0.1:8080/
' 0600
    if [ "$DRY" = "0" ]; then
        # a passphrase-less key readable by the lab user
        if command -v ssh-keygen >/dev/null 2>&1; then
            ssh-keygen -t ed25519 -N '' -C lab -f "$ROOT/backup/id_rsa" >/dev/null 2>&1
            chmod 0644 "$ROOT/backup/id_rsa"
            j_created "$ROOT/backup/id_rsa"
            j_created "$ROOT/backup/id_rsa.pub"
        fi
        cp /etc/shadow /var/backups/lab-shadow.bak 2>/dev/null
        chmod 0644 /var/backups/lab-shadow.bak 2>/dev/null
        j_created /var/backups/lab-shadow.bak
        chmod -R a+rX "$ROOT/backup"
        ok "secrets: $ROOT/backup (creds, .env, id_rsa) + /var/backups/lab-shadow.bak readable"
    fi
}

sc_profile() {
    act "writable /etc/profile.d script"
    put /etc/profile.d/98-lab.sh '#!/bin/sh
# "telemetry" - writable by the lab user, runs for every login shell
true
' 0666
    [ "$DRY" = "0" ] && ok "profile: /etc/profile.d/98-lab.sh is 0666 (root logins execute it)"
}

sc_logrotate() {
    act "logrotate postrotate against a writable dir"
    put /var/log/labapp 'lab log line
' 0666
    put /etc/logrotate.d/labapp '/var/log/labapp {
    daily
    rotate 5
    missingok
    notifempty
    postrotate
        /bin/sh /opt/lab-priv/scripts/rotate-hook.sh
    endscript
}' 0644
    put "$ROOT/scripts/rotate-hook.sh" '#!/bin/sh
true
' 0777
    [ "$DRY" = "0" ] && ok "logrotate: /var/log/labapp is 0666, postrotate runs a 0777 script"
}

sc_docker() {
    if ! command -v docker >/dev/null 2>&1; then warn "docker not installed, skipping"; return 0; fi
    act "lab user in the docker group"
    if [ "$DRY" = "0" ]; then
        getent group docker >/dev/null 2>&1 || groupadd docker
        usermod -aG docker "$LAB_USER" 2>/dev/null
        j_note "GROUP docker $LAB_USER"
        ok "docker: $LAB_USER added to docker group (docker run -v /:/mnt ... )"
    fi
}

sc_nfs() {
    if ! command -v exportfs >/dev/null 2>&1; then warn "nfs-kernel-server not installed, skipping"; return 0; fi
    act "NFS export with no_root_squash"
    mkdir -p /srv/labshare 2>/dev/null
    chmod 0777 /srv/labshare 2>/dev/null
    if [ "$DRY" = "0" ]; then
        grep -q '^/srv/labshare' /etc/exports 2>/dev/null || {
            j_modified /etc/exports
            printf '/srv/labshare *(rw,sync,no_root_squash,no_subtree_check)\n' >> /etc/exports
        }
        exportfs -ra >/dev/null 2>&1
        ok "nfs: /srv/labshare exported no_root_squash"
    fi
}

sc_motd() {
    act "dynamic MOTD hook run by root"
    put /etc/update-motd.d/99-lab '#!/bin/sh
/opt/lab-priv/scripts/motd.sh
' 0755
    put "$ROOT/scripts/motd.sh" '#!/bin/sh
echo "lab motd"
' 0777
    [ "$DRY" = "0" ] && ok "motd: /etc/update-motd.d/99-lab runs a 0777 script on login"
}

# ------------------------------------------------------------------ accounts
ensure_user() {
    if id "$LAB_USER" >/dev/null 2>&1; then
        act "user $LAB_USER already exists"
    else
        if [ "$DRY" = "1" ]; then act "would create user $LAB_USER"; return 0; fi
        useradd -m -s /bin/bash "$LAB_USER" 2>/dev/null || adduser -D "$LAB_USER" 2>/dev/null
        j_note "USER $LAB_USER"
        ok "created $LAB_USER"
    fi
    [ "$DRY" = "0" ] && { echo "$LAB_USER:$LAB_PASS" | chpasswd; ok "password for $LAB_USER set to the documented lab value"; }
}

# --------------------------------------------------------------------- undo
do_undo() {
    [ -f "$JOURNAL" ] || die "no journal at $JOURNAL -- nothing to undo"
    say "replaying the journal backwards..."
    # users and groups first
    awk -F'\t' '$1=="NOTE" && $2 ~ /^USER /{print $2}' "$JOURNAL" | while read -r _ u; do
        id "$u" >/dev/null 2>&1 && { userdel -r "$u" 2>/dev/null && ok "removed user $u"; }
    done
    awk -F'\t' '$1=="NOTE" && $2 ~ /^GROUP /{print $3}' "$JOURNAL" | while read -r u; do
        gpasswd -d "$u" docker >/dev/null 2>&1 && ok "removed $u from docker"
    done
    # stop services we started
    for u in labapp; do
        systemctl is-active "$u" >/dev/null 2>&1 && { systemctl disable --now "$u" >/dev/null 2>&1; ok "stopped $u"; }
    done
    # restore modified files, delete created ones (reverse order)
    tac "$JOURNAL" | while IFS=$'\t' read -r kind a b; do
        case "$kind" in
            CREATED) [ -e "$a" ] && { rm -rf "$a" && ok "deleted $a"; } ;;
            MODIFIED)
                if [ -e "$b" ]; then cp -a "$b" "$a" && ok "restored $a"; else rm -f "$a" && ok "removed $a"; fi ;;
        esac
    done
    rm -f /etc/cron.d/lab-cleanup /etc/cron.d/lab-backup /etc/cron.d/lab-task /etc/sudoers.d/90-lab /etc/sudoers.d/91-labenv
    rm -f /etc/sudoers.d/.90-lab.tmp /etc/sudoers.d/.91-labenv.tmp
    if visudo -c >/dev/null 2>&1; then
        ok "sudoers parses cleanly"
    else
        warn "sudoers still broken -- check /etc/sudoers.d by hand (pkexec rm ...)"
    fi
    rm -rf "$ROOT"
    systemctl daemon-reload >/dev/null 2>&1
    exportfs -ra >/dev/null 2>&1
    mv "$JOURNAL" "$STATE/journal.done.$(date +%s)" 2>/dev/null
    say ""
    ok "undo complete -- snapshot-restore is still the safer route"
}

# ------------------------------------------------------------------- verify
do_verify() {
    say ""
    say "verifying the lab"
    local bad=0
    for f in "$ROOT/bin"/*; do
        [ -e "$f" ] || continue
        if [ -u "$f" ]; then ok "setuid: $f"; else warn "not setuid: $f"; bad=$((bad+1)); fi
    done
    [ -f /etc/cron.d/lab-cleanup ] && ok "cron: lab-cleanup present" || { warn "cron: missing"; bad=$((bad+1)); }
    systemctl is-enabled labapp >/dev/null 2>&1 && ok "systemd: labapp enabled" || { warn "systemd: labapp not enabled"; bad=$((bad+1)); }
    getent group docker 2>/dev/null | grep -q "$LAB_USER" && ok "docker: $LAB_USER in group" || warn "docker: user not in group"
    id "$LAB_USER" >/dev/null 2>&1 && ok "user: $LAB_USER exists" || { warn "user: $LAB_USER missing"; bad=$((bad+1)); }
    # sudo must always parse: a bad fragment here locks you out of sudo itself
    if visudo -c >/dev/null 2>&1; then
        ok "sudoers: parses cleanly"
    else
        warn "sudoers: PARSE ERROR -- sudo is disabled. Remove the offending file in /etc/sudoers.d (pkexec rm ...)"
        bad=$((bad+1))
    fi
    say ""
    if [ "$bad" = "0" ]; then ok "lab looks complete -- log in as $LAB_USER and run linux_local_privesc.sh"
    else warn "$bad item(s) need attention"; fi
}

# =============================================================== main
say ""
say "${BLU}linux_priv_workshop.sh v$VERSION${RST}"
say "${DIM}deliberately vulnerable lab builder -- throwaway VM only${RST}"
say ""

case "$ACTION" in
    undo)   do_undo; exit 0 ;;
    verify) do_verify; exit 0 ;;
esac

if [ "$ASSUME_YES" != "1" ]; then
    cat <<EOF
${YEL}This will deliberately weaken this machine:${RST}
  - setuid copies of shells and interpreters
  - root cron/systemd jobs executing world-writable scripts
  - NOPASSWD sudo rules and preserved LD_PRELOAD
  - file capabilities, planted credentials, writable PATH entries

Run it only on a VM you can throw away. Take a snapshot first.
Type "yes" to continue:
EOF
    read -r ans
    [ "$ans" = "yes" ] || die "aborted"
fi

mkdir -p "$STATE" "$BACKUPS" "$ROOT/bin" "$ROOT/scripts" "$ROOT/app" 2>/dev/null
[ -f "$JOURNAL" ] || : > "$JOURNAL"
printf 'NOTE\tSTART %s\n' "$(date -Is)" >> "$JOURNAL"

ensure_user

for s in $SCENARIOS; do
    want "$s" || { say "${DIM}skip $s${RST}"; continue; }
    "sc_$s"
done

say ""
if [ "$DRY" = "1" ]; then
    say "${DIM}dry run: nothing changed${RST}"
    exit 0
fi
ok "lab built. journal: $JOURNAL"
say ""
say "next:"
say "  su - $LAB_USER        (password: the documented lab value)"
say "  ./linux_local_privesc.sh           # audit it"
say "  ./linux_priv_workshop.sh --verify  # check the lab"
say "  ./linux_priv_workshop.sh --undo    # tear it down"
