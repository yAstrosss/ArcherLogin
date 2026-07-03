package com.yastro.login.authcore.session;

/** Sessão persistente IP-based: conta autenticada de um IP até expirar. */
public record Session(String nameLower, String ip, long expiresAtMillis) {
}
