package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import com.yastro.login.authcore.session.SessionService;
import com.yastro.login.common.AccountKey;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

public final class LogoutCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthState authState;
    private final Messages messages;
    private final SessionService sessions;

    public LogoutCommand(AuthState authState, Messages messages, SessionService sessions) {
        this.authState = authState;
        this.messages = messages;
        this.sessions = sessions;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            return;
        }
        if (!authState.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(msg("logout.not-auth"));
            return;
        }
        authState.clear(player.getUniqueId());
        String name = AccountKey.normalize(player.getUsername());
        // Síncrono e ANTES do disconnect: /logout é raro e revoke é 1 delete por PK indexada
        // (sub-ms SQLite, pooled MySQL). trySubmit (fire-and-forget) podia devolver false sob
        // saturação do pool de auth e DERRUBAR o revoke silenciosamente — sessão sobrevivia a um
        // /logout explícito. Rodar antes do disconnect também fecha a corrida onde um revoke
        // assíncrono terminaria DEPOIS da desconexão, dando brecha pra um reconnect rápido do
        // mesmo IP validar a sessão ainda presente.
        sessions.revoke(name);
        player.disconnect(msg("logout.success"));
    }

    private Component msg(String key) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key));
    }
}
