package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.util.Arrays;

/**
 * {@code /passadmin <nick> <nova senha>}: troca a senha de uma conta. SOMENTE pelo
 * console do proxy, jogadores são recusados (a senha viajaria como argumento e o
 * comando é de operador). Executa no pool de auth (hash Argon2id) e responde no console.
 */
public final class PassAdminCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthService authService;
    private final Messages messages;

    public PassAdminCommand(AuthService authService, Messages messages) {
        this.authService = authService;
        this.messages = messages;
    }

    @Override
    public void execute(Invocation invocation) {
        var source = invocation.source();
        if (source instanceof Player) {
            source.sendMessage(msg("admin.passadmin.console-only"));
            return;
        }
        // defesa-em-profundidade, além de recusar jogadores, exige permissão. O console
        // tem todas as permissões por padrão; uma fonte não-Player não-console (ex.: bridge que
        // executa como console a partir de input remoto) sem a permissão é barrada.
        if (!source.hasPermission("archerlogin.admin.passadmin")) {
            source.sendMessage(msg("admin.passadmin.console-only"));
            return;
        }
        final String[] args = invocation.arguments();
        if (args.length < 2) {
            source.sendMessage(msg("admin.passadmin.usage"));
            return;
        }
        final String nick = args[0];
        final char[] pass = args[1].toCharArray();
        boolean queued = authService.trySubmit(() -> {
            AuthOutcome outcome = authService.adminSetPassword(nick, pass);
            source.sendMessage(msg(outcome.messageKey(), outcome.repl()));
        });
        if (!queued) {
            Arrays.fill(pass, '\0');
            source.sendMessage(msg("error.busy"));
        }
    }

    private Component msg(String key, String... repl) {
        return LEGACY.deserialize(messages.raw(key, repl));
    }
}
