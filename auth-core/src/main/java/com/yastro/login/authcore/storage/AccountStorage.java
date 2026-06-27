package com.yastro.login.authcore.storage;

import java.util.Optional;

/**
 * Persistência de contas. <b>Todas as chamadas são SÍNCRONAS e devem rodar FORA
 * da main thread</b> (o AuthHandler/serviço cuida disso com um executor).
 */
public interface AccountStorage extends AutoCloseable {

    boolean isRegistered(String name) throws Exception;

    Optional<Account> find(String name) throws Exception;

    void register(Account account) throws Exception;

    void updatePassword(String name, String newHash) throws Exception;

    /** Atualiza último IP e horário de login. */
    void touchLogin(String name, String ip, long when) throws Exception;

    /** Marca/desmarca a conta como original (auto-login premium). */
    void setPremium(String name, boolean premium) throws Exception;

    /** Define (ou limpa, com null) o e-mail verificado da conta. */
    void setEmail(String name, String email) throws Exception;

    /** Remove a conta (admin). */
    void delete(String name) throws Exception;

    /** Número de contas registradas a partir de um IP (para limite por IP). */
    int countByRegIp(String ip) throws Exception;

    @Override
    void close();
}
