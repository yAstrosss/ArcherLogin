package com.yastro.login.proxy;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Estado "autenticado" em memória, ligado à conexão (por UUID). Enquanto conectado,
 * trocar de backend nunca repede senha (vantagem do modelo proxy-cêntrico). Perdido
 * ao reiniciar o proxy, a persistência (cookie/token) ainda não está implementada.
 */
public final class AuthState {

    private final Set<UUID> authenticated = ConcurrentHashMap.newKeySet();

    public void markAuthenticated(UUID id) {
        authenticated.add(id);
    }

    public boolean isAuthenticated(UUID id) {
        return authenticated.contains(id);
    }

    public void clear(UUID id) {
        authenticated.remove(id);
    }
}
