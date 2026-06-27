package com.yastro.login.authcore.storage;

/**
 * Conta registrada. {@code email} pode ser null (roadmap 2FA/recuperação).
 */
public record Account(
        String name,
        String uuid,
        String passwordHash,
        String email,
        String regIp,
        String lastIp,
        boolean premium,
        long registeredAt,
        long lastLogin
) {
}
