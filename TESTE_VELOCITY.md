# Checklist de teste — modo Proxy (Velocity)

Roteiro para validar o yAstroLogin atrás de Velocity quando a rede estiver montada.
Faça **na ordem**. Cada item: **[ ] ação → esperado → como verificar**. Pré-requisito:
ler o [SETUP.md](SETUP.md) e o [SECURITY.md](SECURITY.md).

O log forense fica **no proxy** (é um plugin de Velocity), um arquivo por boot em
`plugins/archerlogin/logs/diagnostic-<data>_<hora>.log`. Mantenha um `tail -f` no mais
recente durante TODOS os testes. Tags que ele emite: `FLOOD`, `LOGIN_FAIL`, `THROTTLE`,
`REGISTER_DENY`, `PREMIUM_FAIL`, `BAD_NICK`, `IP_COLLAPSE`.

---

## 0. Topologia do teste

- 1 **Velocity** (proxy) + 1 **backend Paper** (lobby/auth).
- O backend **não** recebe plugin de auth: roda `online-mode=false` + modern forwarding.
  Toda a autenticação acontece no proxy + limbo (LimboAPI).
- Tenha à mão: 1 conta **original** (launcher oficial, mesma versão) e 1 cliente
  **cracked** (offline).

---

## 1. Setup / sanidade (antes de tudo)

- [ ] **Velocity `velocity.toml`**: `online-mode = false`, `player-info-forwarding-mode = "modern"`. → existe `forwarding.secret` na pasta do Velocity.
- [ ] **Backend `config/paper-global.yml`**: `proxies.velocity.enabled: true`, `online-mode: true`, `secret:` = conteúdo do `forwarding.secret` do proxy.
- [ ] **Backend `server.properties`**: `online-mode=false`.
- [ ] **Firewall**: porta do backend aberta **só pro IP do proxy** (essencial — ver §4).
- [ ] **LimboAPI** (dev-build) instalado em `plugins/` do Velocity.
- [ ] Sobe os dois. No boot o proxy deve logar o banner do ArcherLogin + `auth proxy-centric (LimboAPI)`.
  - **Verificar:** se logar `ArcherLogin DESABILITADO: LimboAPI não encontrado`, a dependência falhou → corrigir antes de continuar (sem LimboAPI a auth NÃO sobe, por fail-safe).

---

## 2. Funcional — fluxos felizes

- [ ] **Cracked novo:** entra pelo proxy → preso no limbo → `/register <s> <s>` → autentica, anda/fala liberado.
- [ ] **Cracked relogin:** sai e volta → **pede senha** de novo (`/login <s>`). A sessão por IP está RESERVADA (sem efeito hoje; persistência por cookie foi testada e revertida, ver SECURITY.md §7), então é esperado pedir senha a cada conexão.
- [ ] **Original:** entra com launcher oficial → **auto-login sem senha** (handshake Mojang + modern forwarding) → vai pro `lobby-server`. → backend não pede senha; sem erro.
- [ ] **/trocarsenha** (logado), **/email** + **/recuperar** (com SMTP real configurado): funcionam.

---

## 3. Segurança — o que DEVE falhar

- [ ] **Pirata com nick de original:** cracked tentando o nick de uma conta paga → **barrado** (fail-closed). → `diagnostic`: `PREMIUM_FAIL`.
- [ ] **Throttle por IP:** erra a senha 5x rápido → lockout temporário por IP. → `THROTTLE`.
- [ ] **Lockout por conta (distribuído):** erra a senha de uma conta a partir de IPs diferentes → trava a **conta**; a vítima no IP habitual também é barrada enquanto durar. → `THROTTLE`.
- [ ] **Limite por IP:** registra além de `ip-limit-max-accounts` contas do mesmo IP → recusado. → `REGISTER_DENY`.
- [ ] **Nick inválido:** conexão com nick fora do padrão (chars ilegais) → recusada. → `BAD_NICK`.
- [ ] **Limbo:** jogador não-logado **não aparece** pra quem já está logado (e vice-versa). → entra com 2 contas; a não-logada some da visão/tablist.

---

## 4. Barreira do backend — conexão direta (CRÍTICO)

Sem o proxy, qualquer um que conecte **direto** na porta do backend entraria com **qualquer
nick** (o backend é offline). A barreira é dupla: **modern forwarding** (o Paper recusa quem
não traz o handshake do Velocity) **+ firewall**.

- [ ] **Conexão direta no backend (sem passar pelo proxy):** tentar conectar direto na porta do backend.
  - **Esperado:** o Paper recusa com `This server requires you to connect with Velocity` (sem o handshake de modern forwarding) **e** a porta deve estar fechada no firewall pra IP externo.
  - **Se ENTRAR:** falha grave — firewall e/ou forwarding mal configurados. Parar e corrigir.
- [ ] **Confirmar firewall:** de uma máquina externa, a porta do backend deve estar **fechada** (só o proxy alcança).

> Não há gate HMAC **próprio do plugin** nem `proxy-secret` (o gate antigo do ArcherLogin foi
> removido). A barreira é o HMAC do **modern forwarding do Velocity** (assinado com o
> `forwarding-secret`) — que recusa conexão sem assinatura válida, mas **falha aberto** se o
> secret vazar/for mal configurado — **mais** o firewall, que não depende do secret. Rode os
> dois; nenhum é opcional (ver SECURITY.md).

> Mantenha `allow-cracked-on-premium-nicks=false` no config do proxy. Com `true`, qualquer
> pirata usa o nick de uma conta original como cracked (impersonável).

---

## 5. Coexistência com Sonar (anti-bot de flood)

- [ ] Instalar o **Sonar no Velocity** (camada de conexão, na frente).
- [ ] Conexão legítima (original + cracked) passa pelo Sonar → login normal.
  - **Verificar:** nenhum conflito de fase de login (Sonar verifica antes do limbo; o backend é offline + modern forwarding, sem disputa de handshake).

---

## 6. Carga / flood (validar o que o harness não cobre)

- [ ] **Restart storm:** derrubar/subir o backend com ~todos reconectando (ou simular reconexão em massa pelo proxy). → ver p50/p99 do login; fila cheia (`auth-queue-capacity`) rejeita com "busy" sob pico, mas todos devem logar em poucos segundos.
- [ ] **Flood de conexão:** rajada de conexões (idealmente com Sonar DESLIGADO pra ver o nosso lado). → `diagnostic` deve marcar `FLOOD` acima de `diagnostic-flood-per-min`.
  - **Verificar:** servidor **não** cai (degrada gracioso); o `FLOOD` aparece. Depois religar o Sonar e confirmar que ele corta o flood antes de chegar no backend.
- [ ] **IP colapsado (atrás de frontend TCP):** se rodar atrás de TCPShield/HAProxy/Cloudflare **sem** `proxy-protocol`, muitos nicks distintos colapsam num IP só. → `IP_COLLAPSE` (WARN); ligue `proxy-protocol` no velocity.toml E no frontend pra resolver.

---

## 7. Pós-teste — o que olhar no log forense

Abrir o `logs/diagnostic-<...>.log` mais recente e procurar (grep) cada categoria:
- `FLOOD` → houve pico de conexão? acima do limiar?
- `IP_COLLAPSE` → muitos nicks num IP só (proxy-protocol off atrás de frontend)?
- `PREMIUM_FAIL` → tentativas de usar nick de original / fail-closed.
- `THROTTLE` → brute-force (IP ou conta).
- `REGISTER_DENY` → estouro do limite de contas por IP.
- `LOGIN_FAIL` / `BAD_NICK` → senha errada / nick inválido recusado.

Se cair algo, mande o `diagnostic-<...>.log` do proxy + o `latest.log` do backend: **"claude, procura aqui o que causou a queda"**.

---

## 8. Critério de "aprovado pra produção"

- [ ] §1 a §6 todos passam.
- [ ] Conexão direta no backend **bloqueada** (§4): firewall fechado + Paper exige Velocity.
- [ ] `FLOOD` aparece no log sob ataque + servidor não cai.
- [ ] Sonar cortando flood na frente (§5).
- [ ] `allow-cracked-on-premium-nicks=false` confirmado no config do proxy.
