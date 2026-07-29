package com.krishna.burpagent.launcher;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

final class OfbizDeploymentAgent {
    private final AgentConfiguration config;
    private final CommandRunner commands;

    OfbizDeploymentAgent(AgentConfiguration config, CommandRunner commands) {
        this.config = config;
        this.commands = commands;
    }

    void deployAndWait() throws Exception {
        System.out.println("[OFBiz agent] Building and starting the OFBiz demo container...");
        commands.run(
                List.of("docker", "compose", "up", "--detach", "--build", "ofbiz"),
                config.projectRoot(),
                Duration.ofMinutes(30)
        );
        waitUntilReady();
    }

    private void waitUntilReady() throws Exception {
        String readinessUrl = config.targetUrl();
        Instant deadline = Instant.now().plus(config.ofbizStartupTimeout());
        while (Instant.now().isBefore(deadline)) {
            try {
                HttpsURLConnection connection = open(readinessUrl);
                int status = connection.getResponseCode();
                connection.disconnect();
                if (status < 500) {
                    System.out.println("[OFBiz agent] Ready at " + readinessUrl + " (HTTP " + status + ")");
                    return;
                }
            } catch (IOException ignored) {
                // OFBiz is still starting.
            }
            Thread.sleep(5_000);
        }
        throw new IOException("OFBiz did not become ready before " + config.ofbizStartupTimeout());
    }

    private HttpsURLConnection open(String value) throws IOException, GeneralSecurityException {
        TrustManager[] trustManagers = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());
        HostnameVerifier localOnlyVerifier = (hostname, session) -> hostname.equals(config.targetHost());
        HttpsURLConnection connection = (HttpsURLConnection) new URL(value).openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setHostnameVerifier(localOnlyVerifier);
        connection.setConnectTimeout(5_000);
        connection.setReadTimeout(10_000);
        connection.setInstanceFollowRedirects(false);
        return connection;
    }
}
