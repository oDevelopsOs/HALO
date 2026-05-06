# AgentGuard — AI Agent Security, Made Simple

> **Install it. Forget it. Your files stay safe.**
>
> AgentGuard watches your AI coding assistants (Claude Code, Cursor, Windsurf, OpenCode...)
> and prevents them from deleting your work, leaking your API keys, or going rogue.
> It works at the operating system level — your agents can't bypass it.

---

## Quick Start

```bash
# 1. Build (or download from releases)
cargo build --workspace --exclude agentguard-ebpf --release

# 2. Start the daemon (it runs in the background)
./target/release/agentguard init --output ~/.agentguard/config.toml
./target/release/agentguard-linux --config ~/.agentguard/config.toml &

# 3. Check it's working
./target/release/agentguard status
```

That's it. AgentGuard now watches your AI agents 24/7.

---

## What It Protects

| Threat | How AgentGuard Stops It |
|---|---|
| AI agent deletes your project | **Blocks** the delete at kernel level. The file stays. |
| AI agent leaks your API key | **Intercepts** HTTP traffic, catches secrets before they leave your machine. |
| AI agent modifies `.env` or `.ssh` | **Denies write** to critical files. You get an alert. |
| AI agent runs a malicious script | **Sandboxes** the agent. It can only touch your project folder. |
| Package manager updates an agent | **Auto-heals.** Re-applies protection in 50ms. |

---

## Everyday Commands

```bash
# See what's being protected right now
agentguard status

# Protect folders (you can add as many as you want)
agentguard rules add ~/Projects ~/Documents ~/.ssh

# See everything the AI agents have tried to do
agentguard incidents

# See which AI agents are being watched
agentguard agents

# See stats
agentguard stats

# Create a save point before a big AI session
agentguard snapshot create --label "before-refactor"

# Restore everything if something goes wrong
agentguard snapshot list
agentguard snapshot restore latest --yes

# Pause protection temporarily (30 minutes)
agentguard pause
agentguard resume
```

---

## The Terminal Dashboard

Launch the dashboard and see everything at a glance:

```bash
./target/release/agentguard-tui    # or just: agentguard-tui
```

```
┌─ AgentGuard v0.1.0 ──────────────────────────────────────────────┐
│ [Dashboard] [Zones] [Agents] [Incidents] [Snapshots] [Help]      │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  🛡 PROTECTED                                                      │
│                                                                    │
│  12 protected paths         47 incidents         5 snapshots       │
│  userspace-notify           last 24h             available         │
│                                                                    │
├──────────────────────────────────────────────────────────────────┤
│ AG v0.1.0 | userspace-notify (UserspaceObservation) | 1-6 tabs    │
│ r refresh | p pause | f filter | h help | q quit                  │
└──────────────────────────────────────────────────────────────────┘
```

### How to navigate

| Key | Action |
|---|---|
| `1`-`6` | Switch between tabs |
| `Tab` | Next tab |
| `r` | Refresh data |
| `p` | Pause protection (30 min) |
| `f` | Filter/search incidents |
| `Esc` | Clear filter (press again to quit) |
| `q` | Quit |

### What each tab shows

- **Dashboard** — Overview: protected paths, incidents today, recent activity
- **Zones** — Every folder and file you're protecting
- **Agents** — Every AI agent detected, with session counts and violations
- **Incidents** — Security events timeline. Search with `f` to find specific ones
- **Snapshots** — All your save points. Restore any with a click
- **Help** — Full key reference

---

## How It Works (The Simple Version)

```
YOU START AN AI AGENT (Claude Code, Cursor, etc.)
        │
        ▼
┌──────────────────────────────────┐
│  AGENTGUARD DETECTS IT           │
│  "windsurf is running"           │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  AGENTGUARD PROTECTS YOU         │
│  • Can't delete your files       │
│  • Can't read your .env          │
│  • Can't send secrets to the web │
│  • Everything is logged          │
└──────────────┬───────────────────┘
               │
               ▼
     YOU KEEP WORKING SAFELY
```

### With root access (strongest protection)

AgentGuard uses **eBPF** — Linux kernel technology. The protection lives inside the kernel.
Even if the agent tries to delete a file, the kernel itself says "no." There is no way around it.

### Without root (still protected)

AgentGuard uses **Landlock** — a Linux security feature available since kernel 5.13
(Ubuntu 22.04+). It creates an unbreakable sandbox around the agent. The agent can
only touch files inside your project folder. Everything else is blocked by the kernel.

---

## Installing System-Wide (root)

```bash
# Install as a system service (auto-starts on boot)
sudo ./target/release/agentguard-installer

# Or manually:
sudo cp target/release/agentguard-linux /usr/local/bin/
sudo cp target/release/agentguard /usr/local/bin/
sudo agentguard init --output /etc/agentguard/config.toml
sudo systemctl enable --now agentguard
```

---

## Configuring Agent Detection

AgentGuard detects AI agents automatically. Edit `~/.agentguard/config.toml`:

```toml
# Agents to watch for
[[agent_processes]]
name = "claude-code"
match = { exe_any = ["claude", "claude-code"] }

[[agent_processes]]
name = "windsurf"
match = { exe = "windsurf" }

[[agent_processes]]
name = "opencode"
match = { exe = "opencode" }

# What to do when a violation happens
[on_violation]
kill_process = false          # Don't kill the agent
snapshot_on_violation = true  # Auto-save files before blocking

# Where to protect
protected_dirs = ["~/Documents", "~/Projects", "~/.ssh"]
protected_files = ["~/.env", "~/.netrc", "~/.aws/credentials"]
```

Restart the daemon after editing: `pkill -f agentguard-linux && agentguard-linux &`

---

## Recovering Files

If an AI agent ever manages to delete or corrupt your files (which shouldn't happen
with AgentGuard active, but backups are always good):

```bash
# List all your save points
agentguard snapshot list

# Restore the latest one
agentguard snapshot restore latest --yes

# Or restore a specific one by ID
agentguard snapshot restore d0d496d0 --yes

# Clean up old snapshots (keep last 7 days)
agentguard snapshot cleanup --keep-days 7
```

---

## FAQ

**Q: Will AgentGuard slow down my computer?**
A: No. It uses <10 MB of RAM and <0.1% CPU in idle. Protection happens at the kernel
level — your agents don't even know it's there.

**Q: Do I need to be a Linux expert to use this?**
A: No. Install it once, start the daemon, and forget about it. Use the TUI dashboard
to see what's happening anytime.

**Q: Can the AI agent bypass AgentGuard?**
A: If you're running with root, no — the kernel blocks the agent before it can do
anything. Without root, Landlock creates an unbreakable sandbox. The agent can only
work inside your project folder.

**Q: What if I WANT the agent to modify a file?**
A: Pause protection temporarily: `agentguard pause`. It resumes automatically after
30 minutes. Or add the file to the runtime allowlist.

**Q: Does this work on Windows?**
A: Yes. AgentGuard works on Windows 10+ with AppContainer/LPAC sandboxing and NTFS
file permissions. The experience is the same as Linux.

**Q: Where is my data stored?**
A: Everything is local. Config in `~/.agentguard/`, snapshots in `~/.agentguard/vault/`,
and the database in `~/.agentguard/data/agentguard.db`. Nothing is sent to the cloud
unless you enable telemetry (opt-in).

---

## Advanced: Binary Displacement (no-root sandbox)

For users without root, binary displacement replaces the AI agent's executable with
AgentGuard's shim. The shim applies protection before the agent runs.

```bash
# 1. Build the shim
cargo build --manifest-path crates/agentguard-shim/Cargo.toml --release --target x86_64-unknown-linux-musl

# 2. Displace an agent's binary
mv ~/.npm-global/bin/claude ~/.npm-global/bin/.claude.real
cp crates/agentguard-shim/target/x86_64-unknown-linux-musl/release/agentguard-shim ~/.npm-global/bin/claude

# 3. Now every time 'claude' runs, AgentGuard protects it automatically
#    The auto-heal watcher detects package manager updates and re-applies
```

---

## For Developers

- **Architecture:** [`ARQUITECTURA.MD`](./ARQUITECTURA.MD)
- **Roadmap:** [`docs/ROADMAP-V2.MD`](./docs/ROADMAP-V2.MD)
- **Contributing:** See [`AGENTS.md`](./AGENTS.md)

```bash
# Build and test
cargo build --workspace --exclude agentguard-ebpf
cargo test --workspace --exclude agentguard-ebpf
cargo clippy --workspace --exclude agentguard-ebpf -- -D warnings
```

---

AgentGuard · MIT License · [github.com/oDevelopsOs/HALO](https://github.com/oDevelopsOs/HALO)
