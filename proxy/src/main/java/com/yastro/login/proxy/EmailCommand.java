package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.net.InetSocketAddress;
import java.util.function.Consumer;

/**
 * {@code /email} (pós-auth): vincula um e-mail à conta para recuperação de senha.
 * <ul>
 * <li>{@code /email}, mostra o status do vínculo.</li>
 * <li>{@code /email <endereço>}, envia um código de verificação.</li>
 * <li>{@code /email <código>}, confirma o vínculo.</li>
 * </ul>
 *
 * <p>Registrado como comando do Velocity (não do backend): no setup proxy-cêntrico o
 * backend não tem plugin, então o comando vive no proxy, executa aqui, fica branco +
 * tab-complete no client e NÃO é encaminhado ao backend (a senha/código não vazam).
 */
public final class EmailCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final EmailFlow email;
    private final AuthService authService;
    private final AuthState authState;
    private final Messages messages;

    public EmailCommand(EmailFlow email, AuthService authService, AuthState authState, Messages messages) {
        this.email = email;
        this.authService = authService;
        this.authState = authState;
        this.messages = messages;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            return;
        }
        if (!authState.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(msg("guard.locked"));
            return;
        }
        final String[] args = invocation.arguments();
        // Arg que não é e-mail (sem @) nem código (6 dígitos): mostra o uso em vez de
        // tratar como código e responder "código inválido" (confunde, bug do /email <senha>).
        if (args.length >= 1 && !args[0].contains("@") && !args[0].matches("\\d{6}")) {
            player.sendMessage(msg("email.usage"));
            return;
        }
        final String name = player.getUsername();
        if (!email.tryAcquire(name)) {
            player.sendMessage(msg("login.processing")); // já tem um /email em voo: aguarde
            return;
        }
        final String ip = ip(player);
        // Feedback thread-safe: Player.sendMessage pode ser chamado de qualquer thread.
        final Consumer<AuthOutcome> fb = outcome ->
                player.sendMessage(prefixed(outcome.messageKey(), outcome.repl()));

        boolean queued = authService.trySubmit(() -> {
            try {
                if (args.length == 0) {
                    email.status(name, fb);
                } else if (args[0].contains("@")) {
                    email.linkRequest(name, ip, args[0], fb);
                } else {
                    email.linkConfirm(name, args[0], fb);
                }
            } finally {
                email.release(name);
            }
        });
        if (!queued) {
            email.release(name);
            player.sendMessage(msg("error.busy"));
        }
    }

    private Component msg(String key) {
        return prefixed(key);
    }

    private Component prefixed(String key, String... repl) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key, repl));
    }

    private static String ip(Player player) {
        if (player.getRemoteAddress() instanceof InetSocketAddress addr) {
            return addr.getAddress().getHostAddress();
        }
        return "unknown";
    }
}
