package com.yastro.login.proxy;

/** Resultado puro de uma operação de auth: sucesso + chave de mensagem i18n + placeholders. */
public record AuthOutcome(boolean success, String messageKey, String[] repl) {

    public static AuthOutcome ok(String key, String... repl) {
        return new AuthOutcome(true, key, repl);
    }

    public static AuthOutcome fail(String key, String... repl) {
        return new AuthOutcome(false, key, repl);
    }
}
