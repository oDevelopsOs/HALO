#!/usr/bin/env bash
# extract-syscalls.sh — parse strace output and update seccomp profile JSON.
#
# Usage: extract-syscalls.sh <strace.log> <profile.json>
#
# Reads the strace log, extracts unique syscall numbers, and merges
# them as allow_additions in the profile JSON. Existing entries are
# preserved. New syscalls are added with the current agentguard version.
#
# The strace log format is:
#   syscall_name(args) = result
#
# This script maps syscall names to numbers using ausyscall or
# a builtin lookup table for x86_64.

set -euo pipefail

STRACE_LOG="${1:?missing strace log path}"
PROFILE_JSON="${2:?missing profile json path}"

if [ ! -f "$STRACE_LOG" ]; then
    echo "ERROR: strace log not found: $STRACE_LOG"
    exit 1
fi

# Extract unique syscall names from strace output
# Format: "syscall_name(" at the start of each line
SYSCALL_NAMES=$(grep -oP '^\s*\K[a-zA-Z_][a-zA-Z0-9_]*(?=\()' "$STRACE_LOG" | sort -u || true)

if [ -z "$SYSCALL_NAMES" ]; then
    echo "No syscalls found in trace — nothing to update"
    exit 0
fi

echo "Found $(echo "$SYSCALL_NAMES" | wc -l) unique syscall names"

# x86_64 syscall table (common subset)
# Generated from: ausyscall --dump x86_64
declare -A SYSCALL_MAP
SYSCALL_MAP=(
    ["read"]=0 ["write"]=1 ["open"]=2 ["close"]=3 ["stat"]=4 ["fstat"]=5
    ["lstat"]=6 ["poll"]=7 ["lseek"]=8 ["mmap"]=9 ["mprotect"]=10
    ["munmap"]=11 ["brk"]=12 ["rt_sigaction"]=13 ["rt_sigprocmask"]=14
    ["rt_sigreturn"]=15 ["ioctl"]=16 ["pread64"]=17 ["pwrite64"]=18
    ["readv"]=19 ["writev"]=20 ["access"]=21 ["pipe"]=22 ["select"]=23
    ["sched_yield"]=24 ["mremap"]=25 ["msync"]=26 ["mincore"]=27 ["madvise"]=28
    ["shmget"]=29 ["shmat"]=30 ["shmctl"]=31 ["dup"]=32 ["dup2"]=33
    ["pause"]=34 ["nanosleep"]=35 ["getitimer"]=36 ["alarm"]=37 ["setitimer"]=38
    ["getpid"]=39 ["sendfile"]=40 ["socket"]=41 ["connect"]=42 ["accept"]=43
    ["sendto"]=44 ["recvfrom"]=45 ["sendmsg"]=46 ["recvmsg"]=47
    ["shutdown"]=48 ["bind"]=49 ["listen"]=50 ["getsockname"]=51
    ["getpeername"]=52 ["socketpair"]=53 ["setsockopt"]=54 ["getsockopt"]=55
    ["clone"]=56 ["fork"]=57 ["vfork"]=58 ["execve"]=59 ["exit"]=60
    ["wait4"]=61 ["kill"]=62 ["uname"]=63 ["semget"]=64 ["semop"]=65
    ["semctl"]=66 ["shmdt"]=67 ["msgget"]=68 ["msgsnd"]=69 ["msgrcv"]=70
    ["msgctl"]=71 ["fcntl"]=72 ["flock"]=73 ["fsync"]=74 ["fdatasync"]=75
    ["truncate"]=76 ["ftruncate"]=77 ["getdents"]=78 ["getcwd"]=79
    ["chdir"]=80 ["fchdir"]=81 ["rename"]=82 ["mkdir"]=83 ["rmdir"]=84
    ["creat"]=85 ["link"]=86 ["unlink"]=87 ["symlink"]=88 ["readlink"]=89
    ["chmod"]=90 ["fchmod"]=91 ["chown"]=92 ["fchown"]=93 ["lchown"]=94
    ["umask"]=95 ["gettimeofday"]=96 ["getrlimit"]=97 ["getrusage"]=98
    ["sysinfo"]=99 ["times"]=100 ["ptrace"]=101 ["getuid"]=102
    ["syslog"]=103 ["getgid"]=104 ["setuid"]=105 ["setgid"]=106
    ["geteuid"]=107 ["getegid"]=108 ["setpgid"]=109 ["getppid"]=110
    ["getpgrp"]=111 ["setsid"]=112 ["setreuid"]=113 ["setregid"]=114
    ["getgroups"]=115 ["setresuid"]=117 ["getresuid"]=118
    ["setresgid"]=119 ["getresgid"]=120 ["getpgid"]=121 ["setfsuid"]=122
    ["setfsgid"]=123 ["getsid"]=124 ["capget"]=125 ["capset"]=126
    ["rt_sigpending"]=127 ["rt_sigtimedwait"]=128 ["rt_sigqueueinfo"]=129
    ["rt_sigsuspend"]=130 ["sigaltstack"]=131 ["utime"]=132 ["mknod"]=133
    ["statfs"]=137 ["fstatfs"]=138 ["unshare"]=272 ["setns"]=308
    ["getcpu"]=309 ["getrandom"]=318 ["memfd_create"]=319
    ["openat"]=257 ["mkdirat"]=258 ["mknodat"]=259 ["fchownat"]=260
    ["futimesat"]=261 ["newfstatat"]=262 ["unlinkat"]=263 ["renameat"]=264
    ["linkat"]=265 ["symlinkat"]=266 ["readlinkat"]=267 ["fchmodat"]=268
    ["faccessat"]=269 ["pselect6"]=270 ["ppoll"]=271
    ["io_uring_setup"]=425 ["io_uring_enter"]=426 ["io_uring_register"]=427
    ["openat2"]=437 ["pidfd_open"]=434 ["pidfd_getfd"]=438
    ["close_range"]=436 ["faccessat2"]=439 ["process_madvise"]=440
    ["epoll_pwait2"]=441 ["mount_setattr"]=442
    ["landlock_create_ruleset"]=444 ["landlock_add_rule"]=445
    ["landlock_restrict_self"]=446
    ["futex"]=202 ["set_robust_list"]=273 ["get_robust_list"]=274
    ["epoll_create"]=213 ["epoll_create1"]=291 ["epoll_ctl"]=233
    ["epoll_wait"]=232 ["epoll_pwait"]=281
)

# Map syscall names to numbers
SYSCALL_NUMS=""
for name in $SYSCALL_NAMES; do
    num="${SYSCALL_MAP[$name]:-}"
    if [ -n "$num" ]; then
        SYSCALL_NUMS="$SYSCALL_NUMS $num"
    fi
done

SYSCALL_NUMS=$(echo "$SYSCALL_NUMS" | tr ' ' '\n' | sort -n -u | tr '\n' ' ' | sed 's/ $//')
SYSCALL_COUNT=$(echo "$SYSCALL_NUMS" | wc -w)

echo "Mapped $SYSCALL_COUNT syscalls to numbers"

# Create or update the profile JSON
if [ -f "$PROFILE_JSON" ]; then
    # Merge with existing profile
    EXISTING=$(cat "$PROFILE_JSON" 2>/dev/null || echo '{}')
else
    mkdir -p "$(dirname "$PROFILE_JSON")"
    EXISTING='{}'
fi

# Build allow_additions array
ALLOW_ARR=""
for num in $SYSCALL_NUMS; do
    ALLOW_ARR="$ALLOW_ARR $num,"
done
ALLOW_ARR=$(echo "$ALLOW_ARR" | sed 's/,$//')

CURRENT_VERSION="${AGENTGUARD_VERSION:-0.1.0}"

cat > "$PROFILE_JSON" <<EOF
{
  "version": $(date +%Y%m%d%H),
  "issued_at": $(date +%s),
  "profile": {
    "allow_additions": [${ALLOW_ARR}],
    "deny_enosys_additions": [],
    "min_agentguard_version": "${CURRENT_VERSION}"
  }
}
EOF

echo "Profile written to $PROFILE_JSON"
echo "Sample: $(head -c 200 "$PROFILE_JSON")"
