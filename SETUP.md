# ArcherLogin, Installation

ArcherLogin is **proxy-centric**: the jar runs **only on the Velocity proxy**. The
backends (Paper/etc.) get **no** auth plugin and run with `online-mode=false`. All
authentication happens on the proxy + virtual limbo (LimboAPI).

> **Before anything else:** the **backend firewall** step (section 4) is not optional.
> Without it, anyone can connect straight to the offline backend and join with any name.
> Read [SECURITY.md](SECURITY.md) too.

---

## 0. Build

Requires **JDK 21**. The build uses **Gradle 9.3** (wrapper included).

```bash
./gradlew :proxy:shadowJar
```

Output: `proxy/build/libs/yAstroLogin.jar`.

---

## 1. LimboAPI (required dependency)

Install the **[LimboAPI](https://github.com/Elytrium/LimboAPI)** plugin (Elytrium,
**dev-build** from the master branch) into the **Velocity** `plugins/` folder. Without
it ArcherLogin **does not enable** (fail-safe, it refuses to bring up auth half-wired).

---

## 2. Velocity (`velocity.toml`)

```toml
player-info-forwarding-mode = "modern"
```

With `modern`, Velocity generates a secret file (`forwarding.secret`) in its own folder.
The backends use **the same secret** to trust connections coming from the proxy. **Keep
that secret out of git.**

---

## 3. Proxy plugin

- Copy `yAstroLogin.jar` into the **Velocity** `plugins/` folder.
- On the 1st boot, `plugins/archerlogin/config.properties` is created with the defaults
  below. (An older file gets the new keys added automatically on boot, and is reorganized
  into commented sections while keeping your values.)

Only `config.properties` and `messages.yml` live at the root of the plugin folder, the
rest is internal and goes into subfolders, created on first boot:

```
plugins/archerlogin/
├── config.properties     # configuration (you edit this)
├── messages.yml          # text/language (you edit this)
├── database/             # internal — do not edit
│   ├── accounts.db       # SQLite database (+ -wal/-shm in WAL mode)
│   └── premium-names.txt # premium-nick registry (anti-downgrade, automatic)
└── logs/                 # one forensic log per boot, keeps the last 30
    └── diagnostic-<date>_<time>.log
```

Coming from an older version (files loose at the root)? Migration into `database/` and
`logs/` is **automatic and lossless** on the first 1.8.1 boot.

```properties
# --- Premium policy / flow ---
allow-cracked-on-premium-nicks=false   # true = DANGEROUS (premium nicks become impersonable)
unknown-policy=deny                     # deny (fail-closed, recommended) | offline
lobby-server=lobby                      # destination server after login

# --- Argon2id hash (peak RAM ~ cores x memory-kib) ---
hash-argon2-memory-kib=19456            # floor = OWASP baseline; can only be RAISED
hash-argon2-iterations=2
hash-argon2-parallelism=1

# --- Password rule ---
password-min-length=8

# --- Anti-bruteforce (lockout per IP + per ACCOUNT) ---
bruteforce-max-attempts=5
bruteforce-window-seconds=60
bruteforce-lockout-seconds=300
bruteforce-account-max-attempts=10
bruteforce-account-lockout-seconds=600

# --- Accounts-per-IP limit (anti fake-accounts / bots) ---
ip-limit-enabled=true
ip-limit-max-accounts=3
ip-limit-bypass=127.0.0.1               # comma-separated list; IPs exempt from the limit

# --- Auth pool ---
auth-queue-capacity=128                 # bounded queue; full = "busy" (anti-DoS)

# --- Diagnostics (forensic log: one file per boot in plugins/archerlogin/logs/) ---
diagnostic-enabled=true
diagnostic-flood-per-min=100            # connections/min above this is flagged [FLOOD]

# --- Limbo (unauthenticated state) ---
limbo-dimension=THE_END
limbo-timeout-seconds=60                # 0 = no kick for inactivity

# --- Limbo UI (login prompt) ---
ui-title=true
ui-action-bar=true
ui-sound=true

# --- Database ---
db-type=sqlite                          # sqlite (1 backend) | mysql / mariadb (multiple)
db-host=localhost
db-port=3306
db-name=archerlogin
db-user=root
db-password=                            # PLAIN TEXT, see warning below
db-pool-size=10

# --- E-mail (linking /email + recovery /recuperar) ---
email-enabled=false
email-smtp-host=smtp.gmail.com
email-smtp-port=587
email-smtp-user=
email-smtp-password=                    # PLAIN TEXT, see warning below. Gmail: use an "app password"
email-smtp-from=
email-smtp-encryption=tls               # tls (STARTTLS obrigatório) | ssl | none
email-code-ttl-minutes=10
```

> **Plain-text credentials:** `db-password` and `email-smtp-password` are stored in
> **plain text** in `config.properties`. **Restrict the file permissions** (readable only
> by the proxy user) and **do not commit** this file.

> **STARTTLS obrigatório no modo `tls`:** o e-mail carrega o código de recuperação/vínculo,
> então o modo `tls` exige STARTTLS de verdade — se o servidor SMTP não anunciar a extensão,
> o envio **aborta** em vez de cair para texto puro (fecha o downgrade/strip attack). Um relay
> local **sem** TLS não é suportado nesse modo; use um relay com TLS (recomendado), ou
> `email-smtp-encryption=ssl` na porta 465. O modo aceita só TLS 1.2/1.3 e valida a identidade
> do certificado do servidor.

> Proxy-centric **does not use** `proxy-secret`/HMAC gating, the Mojang online handshake
> + modern forwarding already prove identity on the proxy.

---

## 4. Backends (Paper/etc.), NO plugin + firewall (MANDATORY)

No backend gets an auth plugin. On each backend:

- `server.properties`:
  ```properties
  online-mode=false
  ```
- `config/paper-global.yml` (Paper): accept Velocity forwarding and paste the **same**
  secret from the proxy:
  ```yaml
  proxies:
    velocity:
      enabled: true
      online-mode: true
      secret: 'PASTE_THE_CONTENTS_OF_forwarding.secret_HERE'
  ```

### Firewall (the number-one barrier)

The backend runs offline, so anyone who connects to it **directly** (bypassing the proxy)
joins with **any name**, no password. **This is the only barrier against that:**

- **Block the backend port in the firewall** for every IP that is not the proxy, and/or
- **Bind the backend to a private network** (`server-ip` on an internal LAN, or loopback
  if the proxy is on the same host).

Without this step, everything else (Argon2id, throttle, fail-closed) is bypassable by
connecting straight to the backend. Do not skip it.

---

## 5. First login

1. Start the proxy. The log should show the ArcherLogin banner and
   `auth proxy-centric (LimboAPI)`. If you see `ArcherLogin DESABILITADO: LimboAPI
   não encontrado` (a literal log string the plugin emits), go back to section 1.
2. A **premium** account (official launcher): joins **without a password** (auto-login
   via the Mojang handshake) and goes to `lobby-server`.
3. A **cracked** account: lands in the limbo and uses `/register <password> <password>`,
   then `/login <password>`.

---

## 6. Commands

Pre-auth, inside the limbo (with tab-complete): `/login` (`/l`), `/register` (`/reg`),
`/recuperar`.

Post-auth (proxy commands): `/sair`, `/trocarsenha`, `/email <address|code>`,
`/recuperar`.

Admin: `/passadmin <nick> <new password>`, **proxy console only** (players are refused;
the password would travel as an argument).

There is no **reload** command: changes to `config.properties` require a **proxy
restart**.

---

## 7. MySQL/MariaDB database (multiple backends)

SQLite (`db-type=sqlite`) keeps everything in `plugins/archerlogin/database/accounts.db`,
great for testing or a single proxy. For a real network with multiple backends, use
MySQL/MariaDB:

```properties
db-type=mysql            # uses the MariaDB driver (connects to both MySQL and MariaDB)
db-host=localhost
db-port=3306
db-name=archerlogin
db-user=your_user
db-password=your_password
db-pool-size=10
```

Create the database first (charset `utf8mb4`). The tables are created by the plugin.

---

## 8. E-mail (optional)

For `/recuperar` (password recovery) and `/email` (linking), set `email-enabled=true` and
fill in the `email-smtp-*` keys. For Gmail, generate an **"app password"** and use it in
`email-smtp-password` (not the account's normal password).

---

## 9. Connection anti-bot (flood), companion plugin

ArcherLogin does **not** do connection anti-bot (by design, it handles the limbo and
auth, not connection flooding). To block flood bots **before** login, use a dedicated
proxy plugin such as **[Sonar](https://github.com/jonesdevelopment/sonar)**
(free/open-source). It acts in a layer before authentication.

## 10. Hash tuning (Argon2id) for your hardware

```properties
hash-argon2-memory-kib=19456   # 19 MiB per hash. Peak RAM ~ cores x this value.
hash-argon2-iterations=2
hash-argon2-parallelism=1
```

Hashing concurrency is bounded (~cores), so the peak on restart (many logins at once) is
kept in check. Only **raise** `memory-kib` on a strong dedicated server, the value
**cannot drop** below 19456 (clamped floor = OWASP baseline). Changing the parameters
does **not** invalidate passwords: each account migrates to the new cost on its next
login. Changes only take effect after a **proxy restart**.

---

## Migrating from another login plugin

ArcherLogin reads legacy password hashes on login and transparently rehashes them to Argon2id — players keep their old password. Supported source formats: AuthMe (`$SHA$`, `pbkdf2_sha256$`, bare MD5, bare SHA512), LoginSecurity/AuthMe bcrypt (`$2a$/$2b$/$2y$`).

You must copy the rival hashes into ArcherLogin's table `yastrologin_accounts` (column `password_hash`). Example for AuthMe (MySQL, AuthMe table `authme` with columns `username`,`password`,`ip`,`regdate`,`lastlogin`):

```sql
INSERT IGNORE INTO yastrologin_accounts
  (name_lower, name, uuid, password_hash, reg_ip, last_ip, premium, registered_at, last_login, bedrock)
SELECT LOWER(realname), realname, '', password, ip, ip, 0,
       COALESCE(regdate,0), COALESCE(lastlogin,0), 0
FROM authme;
```

SQLite (AuthMe SQLite `authme` table):
```sql
INSERT OR IGNORE INTO yastrologin_accounts
  (name_lower, name, uuid, password_hash, reg_ip, last_ip, premium, registered_at, last_login, bedrock)
SELECT lower(realname), realname, '', password, ip, ip, 0,
       coalesce(regdate,0), coalesce(lastlogin,0), 0
FROM authme;
```

Notes:
- The `uuid` column can be left empty (`''`); ArcherLogin does not key on it for cracked accounts.
- Non-ASCII passwords hashed by an AuthMe host with a non-UTF-8 default charset may not verify (rare). ASCII passwords always migrate.
- Set `legacy-import.enabled=false` in config to disable legacy verification once migration has settled.
