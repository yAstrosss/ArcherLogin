# ArcherLogin

Sistema de login para redes Minecraft (Java 21). **Roda apenas no proxy
(Velocity)**: toda a autenticação acontece no proxy, antes do jogador tocar num
backend.

> English version: [README.md](README.md)

## Por que ele existe

Redes que aceitam jogadores sem conta Mojang rodam os backends em `online-mode=false`. Nesse
modo o servidor não verifica ninguém com a Mojang, então qualquer um pode entrar com
o nick de outra pessoa, inclusive de administradores. O ArcherLogin fecha essa
brecha no proxy.

## Arquitetura (proxy-cêntrica)

- **Um único plugin, no proxy Velocity.** Os backends **não** têm plugin de auth e
  rodam em `online-mode=false`.
- O jogador não-autenticado fica num **limbo virtual** ([LimboAPI](https://github.com/Elytrium/LimboAPI),
  Elytrium) e só é roteado para um backend real **depois** de logar. Uma conta com senha
  nem chega a tocar no servidor de jogo antes de provar identidade.
- **Conta original (paga):** auto-login via `forceOnlineMode` do Velocity, o
  handshake da Mojang prova a posse da conta no proxy. Quem entra com nick de um
  original sem ter a conta é derrubado **no handshake**, antes de virar player.
- **Conta com senha:** registro/login por senha, digitados **dentro do
  limbo**, nunca passam pelo chat nem pelo console do backend.

## Destaques de segurança

| Recurso | ArcherLogin |
|---|---|
| Hash de senha padrão | **Argon2id** (memory-hard, nº 1 do OWASP), baseline `m=19456, t=2, p=1`, configurável só para **subir** o custo |
| Migração de hash | hashes **bcrypt** importados são aceitos no login e **re-gerados em Argon2id** automaticamente |
| Hashing fora da thread principal | Sim, pool **limitado** com fila com backpressure (teto de RAM no pico de logins do restart) |
| Auto-login de original | Handshake Mojang via `forceOnlineMode` do Velocity, sem senha |
| Proteção de nick original | Quem usa nick de conta paga sem ter a conta é barrado no handshake online-mode |
| Senha no limbo | Digitada dentro do limbo virtual; **nunca** vai ao chat/console do backend |
| Fail-closed na Mojang | Estado `UNKNOWN` (429/erro de rede) **nega** em vez de rebaixar nick premium; registro persistente de nicks premium (anti-downgrade) |
| Anti-bruteforce | Lockout **por IP** + **por conta** (com isenção do último IP-bom da vítima -> sem griefing) |
| Limite de contas por IP | `ip-limit` configurável (anti contas-falsas/bots), com bypass |
| Recuperação/vínculo por e-mail | Código por SMTP (opcional) |
| Log forense | Um arquivo por boot em `logs/diagnostic-<data>_<hora>.log` (mantém os últimos 30) com sinais FLOOD / LOGIN_FAIL / THROTTLE / REGISTER_DENY / PREMIUM_FAIL / BAD_NICK / IP_COLLAPSE |
| Vazamento em tela compartilhada | Args de `login`/`register` digitados por engano num backend são **mascarados** antes de chegar lá |
| SQL | 100% `PreparedStatement` (sem injection), fora da thread principal |

## Funções

- Registro/login por senha, dentro do limbo.
- **Auto-login de originais** via `forceOnlineMode` do Velocity.
- **Recuperação de senha por e-mail** e **vínculo de e-mail** (SMTP, opcional).
- **Limite de contas por IP** e **lockout anti-bruteforce** (por IP + por conta).
- Troca de senha em chat seguro (dentro do limbo) e override por console.
- Banco **SQLite** (1 backend, arquivo) ou **MySQL/MariaDB** (vários backends, HikariCP).
- Mensagens em **pt-BR**; toggles de UI do limbo (title / action-bar / som).

## Comandos

Comandos pré-auth são digitados **dentro do limbo** (com tab-complete):

| Comando | Quando | Descrição |
|---|---|---|
| `/register <senha> <senha>` | limbo (pré-auth) | Cria a conta (alias: `/reg`) |
| `/login <senha>` | limbo (pré-auth) | Autentica (alias: `/l`) |
| `/recuperar` | limbo / pós-auth | Pede um código de recuperação ao e-mail vinculado |
| `/recuperar <código> <nova senha>` | limbo / pós-auth | Redefine a senha com o código recebido |
| `/trocarsenha` | pós-auth | Troca a senha conhecida (cai no limbo para digitar em chat seguro) |
| `/email <endereço>` | pós-auth | Vincula um e-mail à conta |
| `/email <código>` | pós-auth | Confirma o e-mail com o código recebido |
| `/sair` | pós-auth | Encerra a sessão (reconecte para jogar) |
| `/passadmin <nick> <senha>` | **console do proxy** | Define a senha de uma conta (jogadores recusados) |

`recuperar` = esqueci a senha (código por e-mail). `trocarsenha` = sei a senha atual
e quero mudar. `passadmin` só funciona pelo console do proxy, a senha viajaria como
argumento e não deve passar por um jogador.

## Build

Requer **JDK 21** (build com **Gradle 9.3**, wrapper incluído).

```bash
./gradlew :proxy:shadowJar
```

Saída: `proxy/build/libs/yAstroLogin.jar` -> plugin Velocity.

## Início rápido

1. Instale o plugin **LimboAPI** (Elytrium, dev-build) em `plugins/` do Velocity, dependência obrigatória. Sem ela o ArcherLogin **não habilita** (fail-safe).
2. Coloque `yAstroLogin.jar` em `plugins/` do Velocity (apenas no proxy; os backends
   **não** recebem plugin de auth).
3. No `velocity.toml`: `player-info-forwarding-mode = "modern"`. Copie o
   `forwarding-secret` do Velocity para os backends (`config/paper-global.yml` -> `proxies.velocity.secret`) e mantenha esse segredo **fora do git**.
4. Configure cada backend com `online-mode=false` **e bloqueie a porta dele no
   firewall** para tudo que não seja o proxy (passo crítico, veja SECURITY.md).
5. Inicie o proxy. A config (`plugins/archerlogin/config.properties`) e o banco
   SQLite (em `plugins/archerlogin/database/`) são criados sozinhos.
6. Conta original (launcher oficial) entra sem senha. Uma conta com senha usa
   `/register <senha> <senha>` no limbo.

Passo a passo completo e todas as chaves de config em [SETUP.md](SETUP.md).

## Estrutura de pastas

Na pasta do plugin, só `config.properties` e `messages.yml` ficam na raiz (o que você
edita). O resto é interno e fica em subpastas, criadas no primeiro boot:

```
plugins/archerlogin/
├── config.properties     # configuração (seções + um comentário por chave)
├── messages.yml          # textos/idioma
├── database/             # interno — não edite
│   ├── accounts.db       # banco SQLite (+ -wal/-shm em modo WAL)
│   └── premium-names.txt # registro de nicks premium (anti-downgrade, automático)
└── logs/                 # um log forense por boot, mantém os últimos 30
    └── diagnostic-2026-06-29_17-48-16.log
```

Vindo de uma versão antiga (arquivos soltos na raiz)? A migração para `database/` e
`logs/` é **automática e sem perda** no primeiro boot da 1.8.1.

## Segurança e limitações honestas

Leia [SECURITY.md](SECURITY.md): modelo de ameaças (proxy-cêntrico), o que o plugin
protege, os requisitos de deploy obrigatórios (firewall do backend, secret fora do
git, permissão do config) e o que **ainda não** está no escopo (sessão persistente, Bedrock/Floodgate,
2FA, multi-proxy, roadmap).

## Licença

ArcherLogin é software livre sob a **[GNU GPL v3](LICENSE)**.

Copyright (C) 2026 yAstro

Você pode usar, estudar, modificar e redistribuir. Qualquer fork/derivado **deve
permanecer aberto e sob a GPLv3**, ninguém pode fechar o código nem revendê-lo
como software proprietário. Distribuído **sem garantia**, na extensão permitida por
lei (ver o arquivo [LICENSE](LICENSE)).
