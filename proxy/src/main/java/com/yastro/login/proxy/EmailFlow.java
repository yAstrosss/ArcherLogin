package com.yastro.login.proxy;

import com.yastro.login.authcore.auth.AuthThrottle;
import com.yastro.login.authcore.config.AuthConfig;
import com.yastro.login.authcore.config.Messages;
import com.yastro.login.authcore.email.EmailCodes;
import com.yastro.login.authcore.email.EmailService;
import com.yastro.login.authcore.hash.PasswordHasher;
import com.yastro.login.authcore.session.SessionService;
import com.yastro.login.authcore.storage.Account;
import com.yastro.login.authcore.storage.AccountStorage;
import com.yastro.login.common.AccountKey;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Fluxos de e-mail no proxy: vínculo (/email) e recuperação de senha (/recover).
 * Reusa {@link EmailService}/{@link EmailCodes} do auth-core.
 *
 * <p>Os métodos que tocam o storage são SÍNCRONOS, devem rodar dentro do executor de
 * auth (via {@link AuthService#trySubmit}). O envio do e-mail em si é assíncrono
 * (thread própria do EmailService) e o resultado volta pela callback.
 *
 * <p>Velocity-agnóstico: devolve {@link AuthOutcome} por um {@link Consumer}, então o
 * glue (comando/limbo) é quem manda a mensagem no jogador. {@link Messages} é do
 * auth-core (não Velocity), usado aqui só para montar o corpo do e-mail.
 */
public final class EmailFlow {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final EmailService emailService;
    private final EmailCodes emailCodes;
    private final AccountStorage storage;
    private final PasswordHasher hasher;
    private final Messages messages;
    private final AuthConfig cfg;
    private final AuthThrottle emailThrottle; // pedidos de código por IP (anti-bomb)
    private final SessionService sessions;
    /** Máx. 1 operação de e-mail em voo por jogador: barra que um único jogador encha o
     * pool de auth com N tasks de /email|/recuperar (DoS leve do pool). Por nome (lowercase). */
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();

    public EmailFlow(EmailService emailService, EmailCodes emailCodes, AccountStorage storage,
                     PasswordHasher hasher, Messages messages, AuthConfig cfg, SessionService sessions) {
        this.emailService = emailService;
        this.emailCodes = emailCodes;
        this.storage = storage;
        this.hasher = hasher;
        this.messages = messages;
        this.cfg = cfg;
        this.emailThrottle = new AuthThrottle(5, 300, 60); // 5 pedidos / 5min por IP
        this.sessions = sessions;
    }

    /** Reserva o slot (1-em-voo) do jogador. false = já tem uma operação de e-mail rodando. */
    public boolean tryAcquire(String name) {
        return inFlight.add(AccountKey.normalize(name));
    }

    /** Libera o slot. Chamar no finally da task (ou no caminho de fila-cheia). */
    public void release(String name) {
        inFlight.remove(AccountKey.normalize(name));
    }

    /** /email (sem args): status do vínculo. Toca storage, rode no executor. */
    public void status(String name, Consumer<AuthOutcome> fb) {
        try {
            String email = storage.find(name).map(Account::email).orElse(null);
            if (email != null && !email.isBlank()) {
                fb.accept(AuthOutcome.ok("email.status-linked", "email", email));
            } else {
                fb.accept(AuthOutcome.ok("email.status-none"));
            }
        } catch (Exception e) {
            fb.accept(AuthOutcome.fail("error.internal"));
        }
    }

    /** /email &lt;endereço&gt;: gera e envia um código de vínculo. */
    public void linkRequest(String name, String ip, String email, Consumer<AuthOutcome> fb) {
        if (!emailService.isConfigured()) {
            fb.accept(AuthOutcome.fail("email.disabled"));
            return;
        }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            fb.accept(AuthOutcome.fail("email.invalid"));
            return;
        }
        if (!emailThrottle.tryAcquire("email:" + ip)) {
            fb.accept(AuthOutcome.fail("email.cooldown"));
            return;
        }
        String code = emailCodes.issue(name, email, EmailCodes.Kind.LINK);
        if (code == null) {
            fb.accept(AuthOutcome.fail("email.cooldown"));
            return;
        }
        sendCode(email, "email.body-link", code, "email.code-sent", fb);
    }

    /** /email &lt;código&gt;: confirma o vínculo. Toca storage, rode no executor. */
    public void linkConfirm(String name, String code, Consumer<AuthOutcome> fb) {
        EmailCodes.Pending p = emailCodes.consume(name, code, EmailCodes.Kind.LINK);
        if (p == null) {
            fb.accept(AuthOutcome.fail("email.code-invalid"));
            return;
        }
        try {
            storage.setEmail(name, p.email());
            fb.accept(AuthOutcome.ok("email.linked", "email", p.email()));
        } catch (Exception e) {
            fb.accept(AuthOutcome.fail("error.internal"));
        }
    }

    /** /recover: envia um código de recuperação ao e-mail vinculado. Toca storage. */
    public void recoverRequest(String name, String ip, Consumer<AuthOutcome> fb) {
        if (!emailService.isConfigured()) {
            fb.accept(AuthOutcome.fail("email.disabled"));
            return;
        }
        if (!emailThrottle.tryAcquire("recover:" + ip)) {
            fb.accept(AuthOutcome.fail("email.cooldown"));
            return;
        }
        try {
            // resposta NEUTRA, não distingue conta inexistente / sem e-mail / com e-mail
            // (anti-enumeração pré-auth). Só envia de fato quando há conta COM e-mail, mas o jogador
            // SEMPRE vê a mesma mensagem, e o resultado do envio não é revelado.
            Optional<Account> found = storage.find(name);
            String email = found.map(Account::email).filter(e -> e != null && !e.isBlank()).orElse(null);
            if (email != null) {
                String code = emailCodes.issue(name, email, EmailCodes.Kind.RECOVER);
                if (code != null) {
                    String subject = messages.raw("email.subject");
                    String body = messages.raw("email.body-recover", "code", code,
                            "minutes", Integer.toString(cfg.emailCodeTtlMinutes));
                    emailService.send(email, subject, body, ok -> { /* resultado não revelado */ });
                }
            }
            fb.accept(AuthOutcome.ok("recover.neutral"));
        } catch (Exception e) {
            fb.accept(AuthOutcome.fail("error.internal"));
        }
    }

    /** /recover &lt;código&gt; &lt;nova senha&gt;: valida o código e troca a senha. Toca storage. */
    public void recoverApply(String name, String code, char[] newPassword, Consumer<AuthOutcome> fb) {
        try {
            AuthOutcome bad = AuthService.checkNewPassword(newPassword, name, cfg.minPassword); // regra única
            if (bad != null) {
                fb.accept(bad);
                return;
            }
            EmailCodes.Pending p = emailCodes.consume(name, code, EmailCodes.Kind.RECOVER);
            if (p == null) {
                fb.accept(AuthOutcome.fail("email.code-invalid"));
                return;
            }
            storage.updatePassword(name, hasher.hash(newPassword));
            sessions.revoke(AccountKey.normalize(name));
            fb.accept(AuthOutcome.ok("recover.success"));
        } catch (Exception e) {
            fb.accept(AuthOutcome.fail("error.internal"));
        } finally {
            Arrays.fill(newPassword, '\0');
        }
    }

    private void sendCode(String email, String bodyKey, String code, String successKey, Consumer<AuthOutcome> fb) {
        String subject = messages.raw("email.subject");
        String body = messages.raw(bodyKey, "code", code,
                "minutes", Integer.toString(cfg.emailCodeTtlMinutes));
        emailService.send(email, subject, body, ok ->
                fb.accept(ok ? AuthOutcome.ok(successKey) : AuthOutcome.fail("email.send-failed")));
    }
}
