package com.yastro.login.common;

import java.util.Locale;

/**
 * Regra canônica de normalização de nick (case-fold), usada como identificador estável
 * de conta entre os módulos. ÚNICO dono da regra: antes o {@code name.toLowerCase(Locale.ROOT)}
 * vivia copiado em ~18 pontos (storage, e-mail, throttle por conta, registro premium, cache
 * Mojang); aqui é uma só, e um ponto novo de lookup não pode mais "esquecer" de normalizar.
 *
 * <p>{@code Locale.ROOT} é deliberado: evita o "i-turco" ({@code "I".toLowerCase()} em
 * {@code tr_TR} vira {@code "ı"}), que faria a mesma conta gerar chaves diferentes
 * conforme o locale da JVM.
 *
 * <p>{@code normalize(null)} lança {@link NullPointerException}, exatamente como o
 * {@code name.toLowerCase(...)} cru que substitui. O nick é validado/non-null antes de
 * virar chave (PreLogin), então isto não muda nada.
 */
public final class AccountKey {

    private AccountKey() {
    }

    /** Normaliza um nick à forma canônica de chave (minúsculo, {@link Locale#ROOT}). */
    public static String normalize(String rawName) {
        return rawName.toLowerCase(Locale.ROOT);
    }
}
