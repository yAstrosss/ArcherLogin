package com.yastro.login.common;

import java.util.Locale;
import java.util.Objects;

/**
 * Chave canônica de uma conta derivada do nick. ÚNICO dono da regra de normalização
 * (case-fold) usada como identificador estável de conta/sessão/e-mail entre os módulos.
 *
 * <p>Antes a regra {@code name.toLowerCase(Locale.ROOT)} vivia copiada em ~18 pontos
 * (storage, sessão, e-mail, throttle por conta, registro premium, cache Mojang). Aqui é
 * UMA só, um ponto novo de lookup não pode mais "esquecer" de normalizar e introduzir
 * bug de case-sensitivity, e a regra muda num lugar.
 *
 * <p>{@code Locale.ROOT} é deliberado: evita o "i-turco" ({@code "I".toLowerCase()} em
 * {@code tr_TR} vira {@code "ı"}), que faria a mesma conta gerar chaves diferentes
 * conforme o locale da JVM.
 *
 * <p>Comportamento preservado: {@code normalize(null)} lança {@link NullPointerException}
 *, exatamente como o {@code name.toLowerCase(...)} cru que ele substitui. O nick é
 * validado/non-null antes de virar chave (PreLogin), então isto não muda nada.
 */
public final class AccountKey {

    private final String value;

    private AccountKey(String value) {
        this.value = value;
    }

    /**
     * Normaliza um nick à forma canônica de chave (minúsculo, {@link Locale#ROOT}).
     * Use isto em qualquer ponto que precise da chave como {@code String} crua.
     */
    public static String normalize(String rawName) {
        return rawName.toLowerCase(Locale.ROOT);
    }

    /** Embrulha um nick na chave canônica como tipo de valor. */
    public static AccountKey of(String rawName) {
        return new AccountKey(normalize(rawName));
    }

    /** A chave canônica como {@code String} (minúscula). */
    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof AccountKey other && value.equals(other.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }

    // Construtor-cópia defensivo não é necessário: String é imutável.
    static {
        // Falha cedo se alguém remover a dependência de Objects sem querer (no-op em runtime).
        Objects.requireNonNull(Locale.ROOT);
    }
}
