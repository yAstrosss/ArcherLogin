package com.yastro.login.proxy.api.event;

import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.proxy.Player;

import java.util.Objects;

/**
 * Disparado pelo ArcherLogin imediatamente ANTES de autenticar um jogador, dando a
 * outros plugins do proxy a chance de VETAR a autenticação (manutenção, ban de sistema
 * externo, geo-bloqueio, etc.). É o análogo do {@code AuthMeAsyncPreLoginEvent}.
 *
 * <p>Resultado: {@link ResultedEvent.ComponentResult}.
 * {@code setResult(ComponentResult.denied(motivo))} impede a autenticação e desconecta o
 * jogador com o {@code motivo}; {@code ComponentResult.allowed()} (padrão) deixa seguir.
 *
 * <p><b>Threading / semântica de veto</b> (assimetria deliberada, ver relatório):
 * <ul>
 * <li><b>Login por senha</b> (limbo): disparado SÍNCRONO/bloqueante numa thread do pool
 * de auth; o veto é aplicado ANTES de marcar autenticado (veto forte, sem janela).</li>
 * <li><b>Auto-login premium</b>: disparado ASSÍNCRONO logo após a marca (best-effort). A marca
 * de autenticação é síncrona, então entre ela e o veredito do veto o jogador JÁ pode ter
 * sido roteado a um backend; um veto então o desconecta em seguida, mas pode haver uma
 * janela curta em que ele tocou o backend. <b>Veto em {@link LoginType#PREMIUM} é
 * best-effort, NÃO garanta com ele bloqueio forte de acesso ao backend.</b> Para bloqueio
 * forte de premium, use também um listener de {@code ServerPreConnectEvent}.</li>
 * </ul>
 *
 * <p>Falha-ABERTO: se o dispatch do evento quebrar/for interrompido, o ArcherLogin trata
 * como {@code allowed}, a auth primária (senha/Mojang) já passou e um listener de
 * terceiro com bug não deve trancar todos fora.
 */
public final class ArcherPreLoginEvent implements ResultedEvent<ResultedEvent.ComponentResult> {

    private final Player player;
    private final LoginType type;
    private ComponentResult result = ComponentResult.allowed();

    public ArcherPreLoginEvent(Player player, LoginType type) {
        this.player = player;
        this.type = type;
    }

    /** O jogador prestes a ser autenticado. */
    public Player getPlayer() {
        return player;
    }

    /** Como o jogador está autenticando (senha digitada ou auto-login premium). */
    public LoginType getType() {
        return type;
    }

    @Override
    public ComponentResult getResult() {
        return result;
    }

    @Override
    public void setResult(ComponentResult result) {
        this.result = Objects.requireNonNull(result, "result");
    }
}
