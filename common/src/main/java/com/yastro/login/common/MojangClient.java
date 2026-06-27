package com.yastro.login.common;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Descobre se um nick existe como conta original consultando a API pública da
 * Mojang. Usado tanto pelo proxy (decisão online/offline) quanto pelo backend
 * standalone (proteção de nicks de original).
 *
 * <p>Importante: isto só diz se o NOME existe como conta paga. A prova de POSSE é
 * feita pelo {@code forceOnlineMode} (handshake Mojang) no proxy.
 *
 * <p>Devolve TRÊS estados, não um booleano, para o chamador poder falhar
 * FECHADO no caso indecidível:
 * <ul>
 * <li>{@code PREMIUM}, HTTP 200 (existe como conta paga)</li>
 * <li>{@code OFFLINE}, HTTP 404/204 ou nick inválido (não existe / pirata)</li>
 * <li>{@code UNKNOWN}, HTTP 429 (rate-limit) ou erro de rede (indecidível AGORA)</li>
 * </ul>
 *
 * Só {@code PREMIUM} e {@code OFFLINE} são cacheados. {@code UNKNOWN} nunca.
 */
public final class MojangClient {

    public enum Result {
        PREMIUM,
        OFFLINE,
        UNKNOWN
    }

    private static final URI BASE =
            URI.create("https://api.mojang.com/users/profiles/minecraft/");

    /** Nick de Minecraft válido. Fora disto nem consulta a Mojang. */
    public static final Pattern VALID_NICK = Pattern.compile("^[A-Za-z0-9_]{3,16}$");

    private final long cacheTtlMillis;

    private record Entry(Result result, long expiresAt) {
    }

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final ConcurrentHashMap<String, Entry> cache = new ConcurrentHashMap<>();
    // teto do cache. Sem isto, um flood de nicks DISTINTOS válidos (cada 200/404 é cacheado)
    // cresce o heap sem limite (DoS lento controlável por atacante).
    private static final int MAX_CACHE = 50_000;

    public MojangClient() {
        this(5 * 60 * 1000L);
    }

    public MojangClient(long cacheTtlMillis) {
        this.cacheTtlMillis = cacheTtlMillis;
    }

    public CompletableFuture<Result> resolve(String username) {
        // Valida o nick ANTES de qualquer uso/HTTP. Nick malformado = OFFLINE.
        if (username == null || !VALID_NICK.matcher(username).matches()) {
            return CompletableFuture.completedFuture(Result.OFFLINE);
        }

        String key = AccountKey.normalize(username);
        long now = System.currentTimeMillis();

        Entry cached = cache.get(key);
        if (cached != null && cached.expiresAt() > now) {
            return CompletableFuture.completedFuture(cached.result());
        }

        HttpRequest req = HttpRequest.newBuilder()
                .uri(BASE.resolve(username))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .handle((resp, err) -> {
                    if (err != null) {
                        return Result.UNKNOWN; // erro de rede: indecidível, NÃO cacheia
                    }
                    int code = resp.statusCode();
                    if (code == 200) {
                        evictIfNeeded(now);
                        cache.put(key, new Entry(Result.PREMIUM, now + cacheTtlMillis));
                        return Result.PREMIUM;
                    }
                    if (code == 404 || code == 204) {
                        evictIfNeeded(now);
                        cache.put(key, new Entry(Result.OFFLINE, now + cacheTtlMillis));
                        return Result.OFFLINE;
                    }
                    // 429 (rate-limit) ou outro: indecidível, NÃO cacheia.
                    return Result.UNKNOWN;
                });
    }

    /** ao bater o teto, remove os expirados; se ainda cheio (flood), zera o cache
     * (perde-se o cache quente, mas a memória fica limitada). */
    private void evictIfNeeded(long now) {
        if (cache.size() < MAX_CACHE) {
            return;
        }
        cache.values().removeIf(e -> e.expiresAt() <= now);
        if (cache.size() >= MAX_CACHE) {
            cache.clear();
        }
    }
}
