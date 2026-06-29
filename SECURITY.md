# ArcherLogin, Security model

A document for independent review (human or AI). It describes the **current**
state of the plugin, with trade-offs and limitations stated openly.

- **Target:** Minecraft (Java 21), Velocity proxy (3.5.0-SNAPSHOT) + LimboAPI.
- **Architecture:** **proxy-centric**. All authentication lives on the proxy + virtual
  limbo; the backends run **with no auth plugin**, in `online-mode=false`.
- **State:** cracked auth (password register/login in the limbo), premium auto-login
  via Velocity's Mojang handshake, per-IP + per-account lockout, per-IP limit,
  e-mail recovery/linking, and forensic logging are **implemented**. Items in
  §7 are declared roadmap.

---

## 1. Threat model and barrier #1: the backend firewall

The backend runs in `online-mode=false`, it verifies no one. Identity is
established **on the proxy**:

- The proxy resolves the name against Mojang and applies `forceOnlineMode`/`forceOfflineMode` at
  PreLogin.
- The backend trusts the proxy via **modern forwarding** (`player-info-forwarding-mode =
  "modern"`) with the same `forwarding-secret` on both sides. A connection without valid
  forwarding is refused by the backend.

**Mandatory assumption (not optional):** the backend port **must only be
reachable by the proxy**. Modern forwarding's HMAC (signed with the `forwarding-secret`)
**is** a real cryptographic gate — a direct connection that cannot produce a valid
signature is refused by the backend — but it is a **shared-secret** gate that **fails
open**: if the secret leaks (git, logs, backups, a compromised plugin) or a backend does
not enforce modern forwarding, anyone who can reach the port joins as **any name**, with no
password and no Mojang check. The firewall is the barrier that does **not** depend on the
secret staying secret, which is why it ranks first. Run **both**: the secret gates the
proxy→backend channel, the firewall makes a leaked secret useless to an outside attacker.

- **Block the backend port at the firewall** for every IP that is not the proxy's,
  and/or **bind the backend on a private network** (`server-ip` on an internal LAN / loopback
  with the proxy on the same host).
- Keep the `forwarding-secret` **out of git** and with restricted permissions. A leaked
  secret + an exposed port = anyone can forge the origin.

> If you can only guarantee one thing in this deploy, guarantee **this one**. Argon2id,
> throttling and Mojang fail-closed protect the login flow; none of that protects an
> offline backend whose port is open to the internet.

## 2. The basis for "who is premium"

It rests on facts the client does not control:

1. **Mojang handshake** (`forceOnlineMode` on the proxy): the client proves ownership of the
   premium account during login.
2. The proxy only applies `forceOnlineMode` when Mojang confirms the name **exists**
   as a paid account (`MojangClient` -> `PREMIUM`). Anyone using that name without owning the
   account fails the handshake and is dropped by Mojang itself (`Invalid session`).

There is no client-controllable channel that grants privilege: premium/cracked routing
is decided by the handshake result + the UUID version signed by modern forwarding,
not by anything the client sends.

> **`allow-cracked-on-premium-nicks` (default `false`):** if enabled, premium names
> join in offline-mode and become **impersonable** (anyone can log in with a paid
> player's name). The plugin logs a WARN at boot. Leave it `false` unless you know what
> you are doing.

## 3. Password hashing

- **Argon2id** (BouncyCastle, pure Java), default `m=19456 KiB, t=2, p=1`
  (OWASP baseline). Parameters are configurable and **clamped**: the floor is the baseline
  itself (19456 KiB), the config can only **raise** the cost, never drop below the
  recommended value (a weak hash = cheap offline cracking if the database leaks).
- **Calibrated for the peak:** hashing runs on a **bounded pool** (concurrency ~
  cores). Peak RAM at restart is approximately `cores x memory-kib`, **not**
  `players x memory-kib`, which avoids a spike when many players reconnect at once.
- **Never on the proxy thread.** Argon2 costs tens, hundreds of ms; every hash/verify
  goes to the bounded executor; the result returns to the limbo session (thread-safe).
- **Migration:** imported **bcrypt** hashes (`$2a$/$2b$/$2y$`) are accepted at login and
  **re-hashed to Argon2id** automatically. Raising the parameters also triggers a
  re-hash on the next login.
- Password limited to **72 bytes** (bcrypt's limit) with a clear message. Verification is
  done in **constant time**.

## 4. Impersonation via Mojang rate-limit, fail-closed

An attacker could flood the proxy to induce an HTTP 429 from Mojang and register an
admin's name while verification is blind.

- The `MojangClient` distinguishes `UNKNOWN` (429/network error) from `OFFLINE` (404). On
  `UNKNOWN`, the default policy **`unknown-policy=deny`** **denies** the connection, fail-closed,
  closing impersonation even of a premium name **never seen before**.
- A **persistent** `PremiumRegistry` marks every name already confirmed as premium. Even
  with `unknown-policy=offline`, a name that has already appeared as premium keeps being
  denied on `UNKNOWN` (anti-downgrade). `UNKNOWN` is never cached.

> **Trade-off:** with `deny`, a real Mojang outage blocks new logins until things
> recover (impersonation becomes a temporary denial, not a compromise). Whoever
> prioritizes availability uses `unknown-policy=offline` (which protects only
> already-seen names via the persistent registry).

## 5. DoS, brute-force and lockout griefing

- **Login DoS:** **bounded** hash pool + bounded queue (`auth-queue-capacity`)
  with `AbortPolicy`, when the queue is full -> the handler answers "busy" instead of letting
  the queue grow without limit. Each connection also has a **1 auth in flight** lock (cutting
  `/login` spam before the pool).
- **Per-IP brute-force:** `AuthThrottle` per **IP**; after `bruteforce-max-attempts`
  within a window, the IP enters **lockout** (`bruteforce-lockout-seconds`). An IP in lockout
  is rejected **before** being queued (read-only, spends no hash).
- **Per-ACCOUNT brute-force (distributed):** account lockout after
  `bruteforce-account-max-attempts` **wrong** passwords (botnet/proxies on the same target).
  So as **not** to reintroduce name griefing, the lockout has an **exemption for the account's
  last good IP**: the victim, coming from their usual IP, is **never** locked out by third
  parties, only someone coming from a different IP is blocked.
- **Per-IP limit** (`ip-limit`): cap on accounts registered per IP
  (`ip-limit-max-accounts`, with configurable bypass, e.g. `127.0.0.1`), blocking the
  mass creation of fake accounts/bots.
- **Forensic log** (`diagnostic`): one file per boot under `logs/` (e.g.
  `logs/diagnostic-<date>_<time>.log`, the last 30 are kept) with
  `[FLOOD]/[LOGIN_FAIL]/[THROTTLE]/[PREMIUM_FAIL]/[REGISTER_DENY]` events for
  post-incident forensics (not an active defense, an auditable record).

> **Residual:** an attacker can still *globally lock* an account (N wrong passwords from
> varied IPs), but the victim from their usual IP always gets through; the lock only hits
> someone on a new IP during an active attack. `password-min-length` + the Argon2id cost
> remain as a background barrier.

## 6. Other properties

- **Password does not leak in the normal flow:** register/login are typed **inside the
  virtual limbo** and captured by LimboAPI's `onChat`, they do not pass through the Velocity
  dispatcher, other plugins, or the backend console/log.
- **Password masked if typed by mistake on a backend:** if an **already authenticated**
  player types `/login password` on a backend out of habit, the proxy intercepts the
  `CommandExecuteEvent` and **replaces the arguments with random symbols** before
  forwarding, so the password never reaches the backend console.
- **Secure password change:** `/trocarsenha` (no arguments) sends the player back to the
  limbo, where the current and new passwords are typed in secure chat. The password never
  travels as a command argument.
- **Admin password without leaking as an argument:** `/passadmin <nick> <password>` is accepted
  **only from the proxy console**; players are refused (the password would travel as a
  command argument).
- **Register/UUID pinning:** login checks the password **and** that the current UUID
  matches the stored one (case variations of the same name have distinct offline UUIDs).
  The diverging-UUID path uses a dummy hash to match the response time (no timing oracle).
- **Anti-timing-enumeration:** login for a non-existent account also runs a dummy hash,
  so "not registered" cannot be distinguished from "wrong password" by timing.
- **Unauthenticated lockout:** the unauthenticated player stays **trapped in the virtual
  limbo** (LimboAPI) and the proxy **denies** routing to any real backend until they
  authenticate (`ServerPreConnectEvent`). There is no lock based on gameplay events, the
  player simply never reaches the game server before logging in.
- **Dependency fail-closed:** without LimboAPI the plugin **does not enable** (better not
  to start than to let everyone in without auth). With the limbo unavailable, cracked
  connections are **disconnected**, not let through.
- **SQL:** 100% `PreparedStatement`, off the proxy thread. SQLite (file
  `database/accounts.db`, single backend) or MySQL/MariaDB via a HikariCP pool (multiple backends).

## 7. Known limitations / roadmap (declared, not hidden)

- **Persistent session ("stay logged in"):** **not implemented.** Today the "authenticated"
  state lives **in proxy memory** (per connection): while connected, switching backends never
  re-asks for the password, but restarting the proxy or reconnecting requires logging in again.
  Persistence via a **client cookie** was implemented and **tested in-game (2026-06-20), but
  does NOT work**: the Minecraft client clears the transfer cookie on disconnect, so the token
  does not come back on reconnect, a protocol limitation (cookies serve the *transfer* flow
  between servers, not reconnection). The approach was **reverted** and the session subsystem
  (manager/store/config keys) was **removed from the code**; secure session persistence needs a
  different mechanism (roadmap).
- **Bedrock/Floodgate:** **not** supported. A name outside `^[A-Za-z0-9_]{3,16}$` fails
  validation -> it does not register. Explicit integration (Xbox identity = verified,
  separate Java/Bedrock keyspace) is roadmap; do not loosen the name rule manually
  without it (risk of prefix collision / cross-hijacking).
- **2FA (TOTP / Discord):** roadmap.
- **Import/convert from AuthMe/nLogin:** verification of imported bcrypt already exists
  (login accepts and migrates); the **table reader** for other plugins is roadmap.
- **Multi-proxy:** roadmap. MySQL already shares the accounts across proxies, but cross-proxy
  session persistence does not exist (the session subsystem was removed); it depends on a working
  session-persistence mechanism, see above.
- **Live reload:** there is no reload command, config changes (incl. pool size and
  database) require a **proxy restart**.

## 8. Checklist for the reviewer

- [ ] Does auto-login rely only on the Mojang handshake + the forwarding-signed UUID? (yes)
- [ ] Does any client channel/input grant privilege? (no)
- [ ] Does a Mojang 429/error downgrade a premium name (even one never seen)? (no, with `deny`; already-seen is protected even with `offline`)
- [ ] Does name-based lockout allow griefing? (no; per IP + per account WITH an exemption for the victim's good IP)
- [ ] Is the offline backend protected from direct connection? (by modern-forwarding HMAC — a shared secret that fails open if leaked/misconfigured — **plus** the firewall/private bind, which does not depend on the secret; a deploy requirement, §1)
- [ ] Does the password leak in the normal flow (limbo)? (no; captured by onChat, outside the command pipeline)
- [ ] Does a password typed by mistake on a backend leak in the log? (no; args masked by the proxy)
- [ ] Does the admin password leak as an argument? (no; `/passadmin` only from the proxy console)
- [ ] Does the hash run on the proxy thread? (no; bounded pool, result back on the session)
- [ ] Does peak RAM scale with the number of players? (no; with cores x memory-kib)
- [ ] Can the config weaken the hash below the OWASP baseline? (no; floor clamped at 19456 KiB)
- [ ] Is imported bcrypt migrated to Argon2id? (yes, at login)
- [ ] Is SQL parameterized and off the proxy thread? (yes)
- [ ] Without LimboAPI does the plugin let everyone in? (no; it does not enable, fail-safe)
- [ ] Does the "stay logged in" session survive a restart/reconnect? (**no**; in memory, §7; cookie tested and not viable)
- [ ] Are the limitations and roadmap explicit? (§7)

---

*Any divergence between this text and the code should be treated as a bug in the document.*
