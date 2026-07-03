package com.yastro.login.proxy;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent.PreLoginComponentResult;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.yastro.login.authcore.auth.AuthThrottle;
import com.yastro.login.authcore.config.AuthConfig;
import com.yastro.login.authcore.config.Messages;
import com.yastro.login.authcore.email.EmailCodes;
import com.yastro.login.authcore.email.EmailService;
import com.yastro.login.authcore.hash.PasswordHasher;
import com.yastro.login.authcore.storage.AccountStorage;
import com.yastro.login.authcore.storage.StorageFactory;
import com.yastro.login.common.AccountKey;
import com.yastro.login.common.MojangClient;
import com.yastro.login.proxy.api.event.LoginType;
import com.yastro.login.proxy.bedrock.BedrockService;
import com.yastro.login.proxy.bedrock.FloodgateNick;
import net.elytrium.limboapi.api.LimboFactory;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Auth proxy-cêntrica (Velocity + limbo LimboAPI). Toda a autenticação vive no proxy:
 * <ol>
 * <li>PreLogin: resolve o nick na Mojang, PREMIUM força online-mode, OFFLINE força
 * offline-mode, UNKNOWN fail-closed conforme política (anti-impersonação).</li>
 * <li>Pós-login: original verificado ({@code isOnlineMode}) faz auto-login e vai pro
 * lobby; cracked fica preso no limbo virtual.</li>
 * <li>Trava: não-autenticado não alcança backend real (rede de segurança).</li>
 * </ol>
 * Backends reais ficam SEM plugin de auth. Sem gate HMAC (era a arquitetura antiga).
 */
@Plugin(
        id = "archerlogin",
        name = "ArcherLogin",
        version = BuildConstants.VERSION,
        description = "Auth proxy-cêntrica (Velocity + limbo). Original auto-login; cracked no limbo.",
        authors = {"yAstro"},
        dependencies = {@Dependency(id = "limboapi")}
)
public final class YAstroLoginProxy {

    /** Quantos logs forenses por-boot manter em logs/ (poda os mais antigos no boot). */
    private static final int DIAGNOSTIC_LOG_RETAIN = 30;

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private final MojangClient premium = new MojangClient();
    private final AuthState authState = new AuthState();

    private ProxyConfig config;
    private PremiumRegistry premiumRegistry;
    private AccountStorage storage;
    private LimboService limbo;
    private AuthService authService;
    private ExecutorService authExecutor;
    private Messages messages;
    private EmailService emailService;
    private EmailFlow emailFlow;
    private DiagnosticLog diagnostic;
    private FloodCounter floodCounter;
    private CollapsedIpDetector collapsedIp;
    private AuthEvents authEvents;
    private BedrockService bedrock;
    private volatile boolean enabled;

    @Inject
    public YAstroLoginProxy(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onInit(ProxyInitializeEvent event) {
        // Cria database/ + logs/ e migra o layout antigo (arquivos soltos na raiz) antes de
        // abrir o banco/ler o registro premium.
        PluginLayout layout = PluginLayout.prepare(dataDirectory);
        this.config = ProxyConfig.load(dataDirectory);
        this.bedrock = BedrockService.detect(server, config.bedrockEnabled, logger);
        if (bedrock.available()) {
            logger.info("Suporte Bedrock (Floodgate) ATIVO: auto-login de contas Bedrock.");
        }
        this.diagnostic = new DiagnosticLog(layout.logsDir(), config.diagnosticEnabled, DIAGNOSTIC_LOG_RETAIN);
        this.floodCounter = new FloodCounter(config.diagnosticFloodPerMin);
        // Aviso de IP-colapsado: muitos nicks distintos do mesmo IP = proxy-protocol provavelmente
        // off atras de um frontend. So WARN (cooldown 5min), nao bloqueia, bloquear puniria NAT legitimo.
        this.collapsedIp = new CollapsedIpDetector(
                8, 60_000L, 5L * 60_000L, config.ipLimitBypass,
                msg -> { logger.warn(msg); diagnostic.signal("IP_COLLAPSE", msg); });
        this.premiumRegistry = PremiumRegistry.load(layout.databaseDir());

        if (config.allowCrackedOnPremiumNicks) {
            logger.warn("allow-cracked-on-premium-nicks=true: nicks PREMIUM entram em offline-mode "
                    + "e SÃO IMPERSONÁVEIS (qualquer um loga com o nick de um jogador pago). "
                    + "Use só se sabe o que faz.");
        }

        // Fail-safe: sem LimboAPI o plugin NÃO habilita (melhor não ligar do que liberar
        // geral sem auth). orElseThrow falha cedo e claro.
        LimboFactory factory;
        try {
            factory = (LimboFactory) server.getPluginManager()
                    .getPlugin("limboapi")
                    .flatMap(PluginContainer::getInstance)
                    .orElseThrow();
        } catch (Throwable t) {
            logger.error("ArcherLogin DESABILITADO: LimboAPI não encontrado/instância indisponível. "
                    + "Instale o plugin LimboAPI (dev-build master) no Velocity. Auth NÃO está ativa.", t);
            this.enabled = false;
            return;
        }

        // Banco: abre a conexão (prova de conectividade). Falha não derruba o proxy, sem banco a auth cairá fail-closed; aqui só logamos.
        AuthConfig authConfig = config.authConfig();
        try {
            this.storage = StorageFactory.create(authConfig, layout.databaseDir());
        } catch (Exception e) {
            logger.error("ArcherLogin: FALHA ao abrir o banco (type={}). Auth ficará indisponível "
                    + "até o banco voltar.", authConfig.dbType, e);
            this.storage = null;
        }

        this.limbo = new LimboService(server, logger, factory, config);
        this.limbo.init();

        // AuthService + Messages: serviço de auth usado pelo handler do limbo e pelos comandos.
        this.messages = MessagesLoader.load(dataDirectory, logger);
        PasswordHasher hasher = new PasswordHasher(
                authConfig.argonMemoryKib, authConfig.argonIterations, authConfig.argonParallelism,
                authConfig.legacyImportEnabled
                        ? com.yastro.login.authcore.hash.legacy.LegacyHashers.defaultSet()
                        : java.util.List.of());
        AuthThrottle throttle = new AuthThrottle(
                authConfig.maxAttempts, authConfig.attemptWindowSeconds, authConfig.lockoutSeconds);
        // throttle por CONTA (brute-force distribuído). Reaproveita a janela do IP.
        AuthThrottle accountThrottle = new AuthThrottle(
                authConfig.accountMaxAttempts, authConfig.attemptWindowSeconds, authConfig.accountLockoutSeconds);
        // Pool bounded p/ hash+queries. Tamanho conservador: cada hash Argon usa
        // argonMemoryKib de RAM; limitar concorrência evita estouro no pico de logins.
        int poolSize = Math.max(2, authConfig.argonParallelism * 2);
        this.authExecutor = AuthService.newExecutor(poolSize, config.authQueueCapacity);
        this.authService = new AuthService(storage, hasher, throttle, accountThrottle,
                authConfig, config.ipLimitPolicy(), authExecutor);
        // Barramento de eventos públicos (api.event.*): plugins de 3º reagem a/vetam auth.
        this.authEvents = new AuthEvents(server, logger);

        // E-mail (vínculo /email + recuperação /recover). EmailService usa java.util.logging.
        this.emailService = new EmailService(authConfig, java.util.logging.Logger.getLogger("ArcherLogin-Email"));
        EmailCodes emailCodes = new EmailCodes(authConfig.emailCodeTtlMinutes * 60_000L, 60_000L);
        this.emailFlow = new EmailFlow(emailService, emailCodes, storage, hasher, messages, authConfig);

        CommandManager cm = server.getCommandManager();
        CommandMeta logoutMeta = cm.metaBuilder("sair").plugin(this).build();
        cm.register(logoutMeta, new LogoutCommand(authState, messages));
        CommandMeta cpMeta = cm.metaBuilder("trocarsenha").plugin(this).build();
        cm.register(cpMeta, new ChangePasswordCommand(authService, limbo, authState, messages, config, logger));
        // /email é comando do PROXY (backend sem plugin): executa aqui, branco+tab no client.
        CommandMeta emailMeta = cm.metaBuilder("email").plugin(this).build();
        cm.register(emailMeta, new EmailCommand(emailFlow, authService, authState, messages));
        // /recuperar também como comando do proxy: aparece (branco+tab) e no /help do backend;
        // o pré-auth (esqueceu a senha) continua sendo tratado no limbo.
        CommandMeta recoverMeta = cm.metaBuilder("recuperar").plugin(this).build();
        cm.register(recoverMeta, new RecoverCommand(authState, messages));
        // /passadmin: troca de senha SÓ pelo console (jogadores recusados no comando).
        CommandMeta passAdminMeta = cm.metaBuilder("passadmin").plugin(this).build();
        cm.register(passAdminMeta, new PassAdminCommand(authService, messages));

        this.enabled = true;
        printBanner();
    }

    /** Banner de boot. Velocity força um prefixo de log por linha no console
     * (não dá p/ zerar sem hackear o core), então usamos o logger do plugin, prefixo curto [archerlogin]. "ArcherLogin" em verde ANSI (renderiza em
     * console ANSI-capaz; o arquivo de log remove a cor). */
    private void printBanner() {
        final String esc = Character.toString(27); // ESC (0x1b), sem backslash p/ evitar ambiguidade de escape
        final String green = esc + "[32m";
        final String reset = esc + "[0m";
        logger.info("==============================");
        logger.info(" {}ArcherLogin{}", green, reset);
        logger.info(" auth proxy-centric (LimboAPI)");
        logger.info("==============================");
    }

    @Subscribe
    public void onShutdown(ProxyShutdownEvent event) {
        // drena o pool de auth com prazo antes de matar, deixa um register em voo terminar
        // a escrita (evita perder a confirmação no instante do shutdown), depois fecha o storage.
        if (authExecutor != null) {
            shutdownGracefully(authExecutor);
        }
        if (premiumRegistry != null) {
            premiumRegistry.close();
        }
        if (storage != null) {
            try {
                storage.close();
            } catch (Exception ignored) {
            }
        }
        if (limbo != null) {
            limbo.shutdown();
        }
        if (emailService != null) {
            emailService.shutdown();
        }
    }

    /** shutdown ordenado com prazo, espera as tasks em voo terminarem, então força. */
    private static void shutdownGracefully(ExecutorService ex) {
        ex.shutdown();
        try {
            if (!ex.awaitTermination(10, TimeUnit.SECONDS)) {
                ex.shutdownNow();
            }
        } catch (InterruptedException e) {
            ex.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /** PreLogin: resolve-then-force (sem gate). UNKNOWN fail-closed pela política.
     * (Ordering fino p/ coexistência com outros listeners pode ser refinado depois.) */
    @Subscribe
    public EventTask onPreLogin(PreLoginEvent event) {
        if (!enabled) {
            // Fail-closed: sem a dependencia (LimboAPI) a auth nao sobe; recusamos a conexao
            // em vez de deixar passar geral (backend offline = entra com qualquer nick).
            event.setResult(PreLoginComponentResult.denied(Component.text(
                    "Autenticacao indisponivel no momento. Tente mais tarde.")));
            return null;
        }
        final String username = event.getUsername();
        // Bedrock (Floodgate): identidade já provada pelo XUID; aqui só temos o username
        // (com o prefixo Floodgate), não o uniqueId — a checagem autoritativa (isBedrock por
        // UUID) fica pro PostLogin. Aqui só evitamos recusar por nick "inválido" e mandar pro
        // fluxo Mojang um nome que na verdade é Bedrock.
        boolean floodgateName = bedrock.available() && FloodgateNick.looksLikeFloodgate(username);
        // valida o nick no PreLogin (defesa-em-profundidade), não confia que o Velocity já
        // sanitizou. Nick fora de [A-Za-z0-9_]{3,16} é recusado antes de virar chave de conta/log.
        if (!floodgateName && !MojangClient.VALID_NICK.matcher(username).matches()) {
            diagnostic.signal("BAD_NICK", "nick inválido recusado: " + username);
            event.setResult(PreLoginComponentResult.denied(Component.text(
                    "Nick inválido. Use 3 a 16 caracteres: letras, números e _ (underline).")));
            return null;
        }
        if (floodgateName) {
            // Bedrock: offline-mode no lado Java (Floodgate é dono da autenticação). Sem Mojang.
            event.setResult(PreLoginComponentResult.forceOfflineMode());
            return null;
        }
        if (floodCounter.record(System.currentTimeMillis())) {
            diagnostic.signal("FLOOD", "conexões/min acima do limiar; último: " + username);
        }
        // IP real do cliente (Velocity preenche corretamente SE proxy-protocol estiver on quando
        // atras de um frontend). Alimenta o detector de IP-colapsado.
        if (event.getConnection().getRemoteAddress() instanceof InetSocketAddress addr) {
            collapsedIp.observe(addr.getAddress().getHostAddress(),
                    AccountKey.normalize(username), System.currentTimeMillis());
        }
        return EventTask.resumeWhenComplete(
                premium.resolve(username).thenAccept(result -> {
                    String lower = AccountKey.normalize(username);
                    switch (result) {
                        case PREMIUM -> {
                            premiumRegistry.add(lower);
                            if (config.allowCrackedOnPremiumNicks) {
                                event.setResult(PreLoginComponentResult.forceOfflineMode());
                            } else {
                                event.setResult(PreLoginComponentResult.forceOnlineMode());
                            }
                        }
                        case OFFLINE -> event.setResult(PreLoginComponentResult.forceOfflineMode());
                        case UNKNOWN -> {
                            boolean deny = !config.allowCrackedOnPremiumNicks
                                    && (config.unknownPolicyDeny || premiumRegistry.contains(lower));
                            if (deny) {
                                diagnostic.signal("PREMIUM_FAIL", username + " negado (UNKNOWN fail-closed)");
                                event.setResult(PreLoginComponentResult.denied(Component.text(
                                        "Não foi possível verificar sua conta agora "
                                                + "(Mojang indisponível). Tente em instantes.")));
                            } else {
                                event.setResult(PreLoginComponentResult.forceOfflineMode());
                            }
                        }
                    }
                })
        );
    }

    /** Roteamento no login: premium -> auto-login + lobby; cracked -> preso no limbo. */
    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        if (!enabled) {
            return;
        }
        Player player = event.getPlayer();
        UUID id = player.getUniqueId();
        // Bedrock (Floodgate): checagem AUTORITATIVA (por uniqueId, não pelo prefixo de nick
        // usado no PreLogin). Guard anti-hijack: o namespace de prefixo Floodgate é reservado
        // pra conexões Bedrock autoritativas. Uma conexão não-Bedrock é recusada se a conta já
        // está marcada bedrock no banco (isRegisteredBedrock, incondicional — protege mesmo com
        // Floodgate temporariamente fora do ar) OU se o nick tem cara de prefixo Floodgate e o
        // Floodgate está disponível (reserva o namespace pra impedir que um cliente Java registre
        // ".Steve" antes do Bedrock real chegar). Nick Java de verdade nunca começa com caractere
        // fora de [A-Za-z0-9_] (regra Mojang), então isso só barra spoof, nunca jogador legítimo.
        boolean isBedrock = bedrock.available() && bedrock.isBedrock(id);
        if (!isBedrock
                && (isRegisteredBedrock(player.getUsername())
                    || (bedrock.available() && FloodgateNick.looksLikeFloodgate(player.getUsername())))) {
            player.disconnect(Component.text(
                    "Esta conta é Bedrock e só pode entrar via Bedrock/Geyser."));
            logger.warn("Anti-hijack: conexão não-Bedrock recusada para conta bedrock {}", player.getUsername());
            return;
        }
        if (isBedrock && config.bedrockAutoLogin) {
            authState.markAuthenticated(id);               // síncrono, como o premium
            logger.info("Auto-login (Bedrock): {}", player.getUsername());
            persistBedrockAsync(player);                    // best-effort, fora da thread de evento
            authEvents.firePreLoginAsync(player, LoginType.PREMIUM).thenAccept(ev -> {
                if (!player.isActive()) {
                    return;
                }
                if (ev.getResult().isAllowed()) {
                    authEvents.fireLogin(player, LoginType.PREMIUM);
                } else {
                    authState.clear(id);
                    player.disconnect(AuthEvents.denyReason(ev));
                }
            });
            return;
        }
        if (player.isOnlineMode()) {
            // Original verificado pela Mojang -> auto-login. Não precisa do limbo.
            authState.markAuthenticated(player.getUniqueId());
            logger.info("Auto-login (premium): {}", player.getUsername());
            // Veto público best-effort: assíncrono p/ NÃO travar a thread de evento nem
            // reintroduzir corrida com ServerPreConnect (a marca acima é síncrona). Um plugin
            // que negar desfaz a marca e desconecta (janela curta); senão dispara o LoginEvent.
            authEvents.firePreLoginAsync(player, LoginType.PREMIUM).thenAccept(ev -> {
                if (!player.isActive()) {
                    return;
                }
                if (ev.getResult().isAllowed()) {
                    authEvents.fireLogin(player, LoginType.PREMIUM);
                } else {
                    authState.clear(player.getUniqueId());
                    player.disconnect(AuthEvents.denyReason(ev));
                }
            });
            return;
        }
        // Cracked: precisa do limbo. Se indisponível, desconecta (fail-closed, sem estado mudo).
        if (limbo == null || !limbo.isReady()) {
            player.disconnect(Component.text(
                    "Autenticação indisponível no momento. Tente mais tarde."));
            logger.error("Cracked {} desconectado: limbo indisponível.", player.getUsername());
            return;
        }
        limbo.enterLimbo(player, new AuthLimboHandler(
                authService, limbo, authState, messages, storage, config, logger, emailFlow, diagnostic, authEvents));
        logger.info("Cracked no limbo: {}", player.getUsername());
    }

    /** Lê síncrono e barato só o flag bedrock; usado no guard anti-hijack. Storage nulo -> false.
     * Leitura JDBC bloqueante NA thread de evento é deliberada aqui (trade-off documentado):
     * SQLite é sub-ms e MySQL é pooled; o custo é aceitável pra um guard que roda 1x por login
     * e é o que impede uma conta bedrock ser sequestrada por uma conexão Java comum. */
    private boolean isRegisteredBedrock(String name) {
        if (storage == null) {
            return false;
        }
        try {
            return storage.find(name).map(a -> a.bedrock()).orElse(false);
        } catch (Exception e) {
            return false; // falha de storage não deve virar oráculo; trata como não-bedrock
        }
    }

    /** Cria a linha da conta Bedrock (sem senha) se ainda não existir. Roda no pool de auth. */
    private void persistBedrockAsync(Player player) {
        if (storage == null) {
            return;
        }
        String name = player.getUsername();
        String uuid = player.getUniqueId().toString();
        String ip = player.getRemoteAddress() != null
                ? player.getRemoteAddress().getAddress().getHostAddress() : "";
        authExecutor.execute(() -> {
            try {
                if (!storage.isRegistered(name)) {
                    long now = System.currentTimeMillis();
                    storage.register(new com.yastro.login.authcore.storage.Account(
                            name, uuid, "", null, ip, ip, false, now, now, true));
                } else {
                    storage.touchLogin(name, ip, System.currentTimeMillis());
                }
            } catch (Exception e) {
                logger.warn("Falha ao persistir conta Bedrock {}: {}", name, e.toString());
            }
        });
    }

    /** Trava: não-autenticado não alcança backend real (o limbo é virtual e não passa aqui).
     * Roda em PostOrder.LAST para o deny ser autoritativo mesmo se outro plugin tiver
     * liberado o roteamento antes (no Velocity o ultimo resultado vence). */
    @Subscribe(order = PostOrder.LAST)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        if (!enabled) {
            // Fail-closed: plugin desabilitado (ex.: LimboAPI ausente) NUNCA libera backend.
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            return;
        }
        Player player = event.getPlayer();
        if (!authState.isAuthenticated(player.getUniqueId())) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
    }

    /** Limpa o estado ao desconectar (sem vazamento de sessão pendente). */
    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        authState.clear(event.getPlayer().getUniqueId());
    }

    /**
     * Mascara args de comandos sensíveis de auth digitados DEPOIS do login (já num
     * backend), p/ a senha não vazar em texto puro no console do backend
     * ("issued server command: /login senha"). Pré-auth o jogador está no limbo e
     * não passa por aqui, então o login normal não é afetado.
     */
    @Subscribe
    public void onCommandExecute(CommandExecuteEvent event) {
        if (!enabled) {
            return;
        }
        if (!(event.getCommandSource() instanceof Player player)) {
            return;
        }
        if (!authState.isAuthenticated(player.getUniqueId())) {
            return; // pré-auth = limbo; não toca (login precisa funcionar lá)
        }
        String masked = SensitiveCommandFilter.maskedOrNull(event.getCommand());
        if (masked != null) {
            event.setResult(CommandExecuteEvent.CommandResult.forwardToServer(masked));
        }
    }
}
