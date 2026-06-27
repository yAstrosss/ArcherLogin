package com.yastro.login.proxy.api.event;

import com.velocitypowered.api.proxy.Player;

/**
 * Disparado pelo ArcherLogin DEPOIS que um jogador registrou a conta com sucesso (via
 * /register no limbo). Notificação (não cancelável). É o análogo do {@code RegisterEvent}
 * do AuthMe.
 *
 * <p>Como o registro também autentica, um {@link ArcherLoginEvent} é disparado em seguida
 * no mesmo fluxo.
 */
public final class ArcherRegisterEvent {

    private final Player player;

    public ArcherRegisterEvent(Player player) {
        this.player = player;
    }

    /** O jogador que acabou de registrar. */
    public Player getPlayer() {
        return player;
    }
}
