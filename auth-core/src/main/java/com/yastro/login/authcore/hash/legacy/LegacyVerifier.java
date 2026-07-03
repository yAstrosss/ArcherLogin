package com.yastro.login.authcore.hash.legacy;

/** Verificador de um formato de hash legado (import de plugin rival). Só LÊ; nunca gera. */
public interface LegacyVerifier {
    /** True se {@code stored} tem a cara deste formato. */
    boolean matches(String stored);
    /** Verifica a senha contra o hash legado. Fail-closed: malformado -> false, nunca lança. */
    boolean verify(char[] password, String stored);
    /** Id curto p/ log/diagnóstico (ex.: "authme-sha256"). */
    String id();
}
