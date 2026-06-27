package com.yastro.login.authcore.email;

import com.yastro.login.authcore.config.AuthConfig;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Envio de e-mail via SMTP (Jakarta Mail / Angus). Usado só para mandar códigos de
 * vínculo e de recuperação. Envia em uma thread dedicada (SMTP bloqueia em rede).
 */
public final class EmailService {

    private final AuthConfig config;
    private final Logger logger;
    private final ExecutorService sender = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ArcherLogin-Email");
        t.setDaemon(true);
        return t;
    });

    public EmailService(AuthConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
    }

    /** True se o e-mail está ligado e minimamente configurado. */
    public boolean isConfigured() {
        return config.emailEnabled
                && notBlank(config.emailHost) && notBlank(config.emailFrom);
    }

    /** Envia assíncrono; {@code onResult} recebe true/false (na thread de envio). */
    public void send(String to, String subject, String body, Consumer<Boolean> onResult) {
        sender.execute(() -> {
            boolean ok = false;
            try {
                sendBlocking(to, subject, body);
                ok = true;
            } catch (Exception e) {
                logger.log(Level.WARNING, "Falha ao enviar e-mail para " + to + ": " + e.getMessage());
            }
            onResult.accept(ok);
        });
    }

    private void sendBlocking(String to, String subject, String body) throws Exception {
        String enc = config.emailEncryption == null ? "tls" : config.emailEncryption;
        boolean ssl = "ssl".equals(enc);

        Properties props = new Properties();
        // Classes de transporte explícitas: robusto em jar shaded (não depende de
        // META-INF/javamail.providers ser encontrado).
        props.put("mail.smtp.class", "org.eclipse.angus.mail.smtp.SMTPTransport");
        props.put("mail.smtps.class", "org.eclipse.angus.mail.smtp.SMTPSSLTransport");
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");
        props.put("mail.smtps.connectiontimeout", "10000");
        props.put("mail.smtps.timeout", "10000");
        if ("tls".equals(enc)) {
            props.put("mail.smtp.starttls.enable", "true");
        }
        if (ssl) {
            props.put("mail.smtps.ssl.enable", "true");
        }

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(config.emailUser, config.emailPassword);
            }
        });

        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(config.emailFrom));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        msg.setSubject(subject, "UTF-8");
        msg.setText(body, "UTF-8");

        try (Transport transport = session.getTransport(ssl ? "smtps" : "smtp")) {
            transport.connect(config.emailHost, config.emailPort, config.emailUser, config.emailPassword);
            transport.sendMessage(msg, msg.getAllRecipients());
        }
    }

    public void shutdown() {
        sender.shutdownNow();
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
