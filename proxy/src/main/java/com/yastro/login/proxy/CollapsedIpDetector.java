package com.yastro.login.proxy;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Detecta "IP colapsado": muitos nicks DISTINTOS chegando do MESMO IP numa janela
 * curta. Sinal forte de {@code proxy-protocol} DESLIGADO atrás de um frontend TCP
 * (TCPShield / HAProxy / Cloudflare Spectrum): o {@code getRemoteAddress()} do Velocity
 * devolve o IP do frontend, então TODOS os jogadores colapsam num IP só, e aí o
 * anti-bruteforce ({@link com.yastro.login.authcore.auth.AuthThrottle}) e o ip-limit
 * ({@link IpLimitPolicy}) passam a punir jogadores legítimos.
 *
 * <p>NÃO bloqueia: só dispara um aviso (com cooldown) pro operador. Bloquear seria pior
 *, puniria NAT/CGNAT legítimo. O operador lê o aviso e: liga {@code proxy-protocol=true}
 * no {@code velocity.toml} (e no frontend), ou adiciona o IP em {@code ip-limit-bypass}
 * se for um IP compartilhado legítimo.
 *
 * <p>Thread-safe ({@code PreLogin} dispara concorrente). Janela e custo limitados por
 * tempo e por teto duro de entradas (anti-flood de memória).
 */
public final class CollapsedIpDetector {

    private record Entry(long time, String ip, String user) {}

    private final int distinctNickThreshold;
    private final long windowMillis;
    private final long warnCooldownMillis;
    private final int maxEntries;
    private final Set<String> bypass;
    private final Consumer<String> warn;

    private final ArrayDeque<Entry> window = new ArrayDeque<>();
    // Colapso STICKY: um IP que já disparou o limiar fica marcado colapsado até o operador
    // reiniciar/reconfigurar. Fecha o furo onde um vale de tráfego (a janela deslizante cai
    // abaixo do limiar) reabriria o auto-login por sessão num deployment genuinamente colapsado.
    private final Set<String> stickyCollapsed = ConcurrentHashMap.newKeySet();
    private boolean warned = false;
    private long lastWarn = 0L;

    public CollapsedIpDetector(int distinctNickThreshold, long windowMillis,
                               long warnCooldownMillis, Set<String> bypass, Consumer<String> warn) {
        this.distinctNickThreshold = distinctNickThreshold;
        this.windowMillis = windowMillis;
        this.warnCooldownMillis = warnCooldownMillis;
        this.maxEntries = 4096;
        this.bypass = bypass;
        this.warn = warn;
    }

    /**
     * Registra uma conexão (nick já validado). Dispara o aviso uma vez por cooldown se o
     * IP que acabou de conectar acumulou {@code >= distinctNickThreshold} nicks distintos
     * na janela. IPs em {@code bypass} (inclui loopback) são ignorados.
     */
    public synchronized void observe(String ip, String userLower, long now) {
        if (ip == null || bypass.contains(ip)) {
            return;
        }
        window.addLast(new Entry(now, ip, userLower));
        // Evict por tempo + teto duro (sob flood a janela não cresce sem limite).
        while (!window.isEmpty()
                && (now - window.peekFirst().time() > windowMillis || window.size() > maxEntries)) {
            window.pollFirst();
        }
        // Conta nicks DISTINTOS do IP recém-conectado dentro da janela.
        Set<String> nicks = new HashSet<>();
        for (Entry e : window) {
            if (e.ip().equals(ip)) {
                nicks.add(e.user());
            }
        }
        // !warned cobre o 1o aviso sem aritmética de sentinela (evita overflow com now pequeno).
        if (nicks.size() >= distinctNickThreshold) {
            stickyCollapsed.add(ip); // uma vez colapsado, permanece (não reabre em vale de tráfego)
        }
        if (nicks.size() >= distinctNickThreshold && (!warned || now - lastWarn > warnCooldownMillis)) {
            warned = true;
            lastWarn = now;
            warn.accept("IP colapsado: " + nicks.size() + " nicks distintos do mesmo IP " + ip
                    + " em " + (windowMillis / 1000L) + "s. Provavel proxy-protocol DESLIGADO atras de um "
                    + "frontend (TCPShield/HAProxy/Cloudflare) -> o IP real esta mascarado e o "
                    + "anti-bruteforce/ip-limit vao punir jogadores legitimos. Ligue proxy-protocol=true "
                    + "no velocity.toml (e no frontend). Se " + ip + " e um IP compartilhado legitimo, "
                    + "adicione em ip-limit-bypass.");
        }
    }

    /**
     * Consulta (sem alterar estado: não evict, não mexe no cooldown do WARN) se {@code ip}
     * está colapsado AGORA, usando o MESMO limiar de nicks distintos que dispara o WARN.
     * Usado pelo gate de auto-login por sessão: sessão é chaveada por (nick, ip), então um IP
     * colapsado (proxy-protocol provavelmente off atrás de um frontend) transforma a sessão-por-IP
     * num bypass universal — qualquer nick com sessão salva auto-loga por qualquer conexão que
     * caia nesse IP mascarado.
     */
    public synchronized boolean isCollapsed(String ip, long nowMillis) {
        if (ip == null || bypass.contains(ip)) {
            return false;
        }
        if (stickyCollapsed.contains(ip)) {
            return true; // já colapsado antes: não confia no IP p/ sessão mesmo que a janela tenha esvaziado
        }
        Set<String> nicks = new HashSet<>();
        for (Entry e : window) {
            if (nowMillis - e.time() <= windowMillis && e.ip().equals(ip)) {
                nicks.add(e.user());
            }
        }
        return nicks.size() >= distinctNickThreshold;
    }
}
