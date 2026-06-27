package com.yastro.login.proxy.api.event;

/**
 * Como o jogador se autenticou no ArcherLogin.
 */
public enum LoginType {

    /** Senha digitada (/login ou /register no limbo). */
    PASSWORD,

    /** Auto-login de conta original verificada pela Mojang (sem senha). */
    PREMIUM
}
