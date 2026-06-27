# ArcherLogin

Login system for Minecraft (Java 21) networks. **Proxy-only (Velocity)**: all
authentication happens on the proxy, before the player ever touches a backend.

> Portuguese version: [README_PT.md](README_PT.md)

> The product name is **ArcherLogin**. The Java package (`com.yastro.login`), the
> table (`yastrologin_accounts`) and the jar (`yAstroLogin.jar`) keep the old internal
> name on purpose, renaming would break existing databases and installs.

## Why it exists

Networks that accept offline players run their backends with `online-mode=false`. In
that mode the server doesn't verify anyone with Mojang, so anyone can join using
someone else's name, including admins. ArcherLogin closes that gap on the proxy.

## Architecture (proxy-centric)

- **One plugin, on the Velocity proxy.** Backends carry **no** auth plugin and run
  with `online-mode=false`.
- An unauthenticated player sits in a **virtual limbo**
  ([LimboAPI](https://github.com/Elytrium/LimboAPI), Elytrium) and is only routed to a
  real backend **after** logging in. A cracked player never touches the game server
  before proving identity.
- **Premium (paid account):** auto-login via Velocity's `forceOnlineMode`, the Mojang
  handshake proves account ownership on the proxy. Anyone joining with a premium name
  without owning the account is rejected **at the handshake**, before becoming a player.
- **Cracked (offline):** password register/login, typed **inside the limbo**, they
  never pass through the backend chat or console.

> **The number-one barrier is the backend firewall.** Because backends run offline,
> their port **must** be unreachable from the internet (firewall or private-network
> bind), it is the **only** defense against someone connecting straight to a backend,
> bypassing the proxy (whoever gets through joins as any name). See
> [SECURITY.md](SECURITY.md) and [SETUP.md](SETUP.md).

## Security highlights

| Feature | ArcherLogin |
|---|---|
| Default password hash | **Argon2id** (memory-hard, OWASP #1), baseline `m=19456, t=2, p=1`, configurable only to **raise** the cost |
| Hash migration | imported **bcrypt** hashes are accepted at login and **re-hashed to Argon2id** automatically |
| Hashing off the main thread | Yes, **bounded** pool with backpressure (caps RAM during login storms) |
| Premium auto-login | Mojang handshake via Velocity `forceOnlineMode`, no password |
| Premium-name protection | Anyone using a paid account's name without owning it is blocked at the online-mode handshake |
| Password in limbo | Typed inside the virtual limbo; **never** reaches the backend chat/console |
| Mojang fail-closed | `UNKNOWN` state (429/network error) **denies** instead of downgrading a premium name; persistent premium-name registry (anti-downgrade) |
| Anti-bruteforce | Lockout **per IP** + **per account** (victim's last good IP exempt -> no griefing) |
| Per-IP account limit | Configurable `ip-limit` (anti fake-accounts/bots), with bypass |
| E-mail recovery / linking | SMTP code (optional) |
| Forensic log | Rotating `diagnostic.log` with FLOOD / LOGIN_FAIL / THROTTLE / REGISTER_DENY / PREMIUM_FAIL signals |
| Screen-share leak | Args of `login`/`register` typed by mistake on a backend are **masked** before they get there |
| SQL | 100% `PreparedStatement` (no injection), off the main thread |

## Features

- Password register/login for offline accounts, inside the limbo.
- **Premium auto-login** via Velocity `forceOnlineMode`.
- **E-mail password recovery** and **e-mail linking** (SMTP, optional).
- **Per-IP account limit** and **anti-bruteforce lockout** (per IP + per account).
- Password change in a secure chat (inside the limbo) and console override.
- **SQLite** (single backend, file) or **MySQL/MariaDB** (multi-backend, HikariCP).
- **pt-BR** messages; limbo UI toggles (title / action-bar / sound).

## Commands

Pre-auth commands are typed **inside the limbo** (with tab-complete). Command keywords
are PT-BR:

| Command | When | Description |
|---|---|---|
| `/register <pass> <pass>` | limbo (pre-auth) | Create the account (alias: `/reg`) |
| `/login <pass>` | limbo (pre-auth) | Authenticate (alias: `/l`) |
| `/recuperar` | limbo / post-auth | Request a recovery code to the linked e-mail |
| `/recuperar <code> <new pass>` | limbo / post-auth | Reset the password with the received code |
| `/trocarsenha` | post-auth | Change a known password (drops you into the limbo to type it securely) |
| `/email <address>` | post-auth | Link an e-mail to the account |
| `/email <code>` | post-auth | Confirm the e-mail with the received code |
| `/sair` | post-auth | End the session (reconnect to play) |
| `/passadmin <nick> <pass>` | **proxy console** | Set an account's password (players refused) |

`recuperar` = forgot the password (e-mail code). `trocarsenha` = you know the current
password and want to change it. `passadmin` only works from the proxy console, the
password would travel as an argument and must not pass through a player.

## Build

Requires **JDK 21** (built with **Gradle 9.3**, wrapper included).

```bash
./gradlew :proxy:shadowJar
```

Output: `proxy/build/libs/yAstroLogin.jar` -> Velocity plugin.

## Quick start

1. Install the **LimboAPI** (Elytrium, dev-build) plugin into the Velocity `plugins/`, required dependency. Without it ArcherLogin **does not enable** (fail-safe).
2. Drop `yAstroLogin.jar` into the Velocity `plugins/` (proxy only; backends get **no**
   auth plugin).
3. In `velocity.toml`: `player-info-forwarding-mode = "modern"`. Copy the Velocity
   `forwarding-secret` to the backends (`config/paper-global.yml` -> `proxies.velocity.secret`) and keep that secret **out of git**.
4. Configure each backend with `online-mode=false` **and block its port in the
   firewall** to anything but the proxy (critical step, see SECURITY.md).
5. Start the proxy. The config (`plugins/archerlogin/config.properties`) and the SQLite
   database are created automatically.
6. A premium account (official launcher) joins without a password. A cracked player
   uses `/register <pass> <pass>` in the limbo.

Full walkthrough and every config key in [SETUP.md](SETUP.md).

## Honest security & limitations

Read [SECURITY.md](SECURITY.md) for the threat model (proxy-centric), what the plugin
protects, the mandatory deploy requirements (backend firewall, secret out of git,
config-file permissions), and what is **not in scope yet** (persistent session, Bedrock/Floodgate,
2FA, multi-proxy, roadmap).

## License

ArcherLogin is free software under the **[GNU GPL v3](LICENSE)**.

Copyright (C) 2026 yAstro

You may use, study, modify and redistribute it. Any fork/derivative **must stay open
and under GPLv3**, nobody may close the source or resell it as proprietary software.
Distributed **without warranty**, to the extent permitted by law (see [LICENSE](LICENSE)).
