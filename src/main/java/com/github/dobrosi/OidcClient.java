package com.github.dobrosi;

import java.awt.Desktop;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class OidcClient {
    private final OkHttpClient client;
    private final ObjectMapper objectMapper;
    private final MessageDigest messageDigest;
    private final String authority;
    private final String clientId;
    private final URI redirectUri;
    private final String scope;
    private OpenidConfiguration openidConfiguration;

    public OidcClient(final String authority, final String clientId, final String redirectUri, final String scope) {
        this.authority = authority;
        this.clientId = clientId;
        this.redirectUri = URI.create(redirectUri);
        this.scope = scope;
        client = new OkHttpClient();
        objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        getEndpoints();
    }

    public TokenResponse authorize() {
        try {
            String codeVerifier = generateCodeVerifier();
            return waitForAuthorizationCode(codeVerifier);
        } catch (IOException | InterruptedException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private void getEndpoints() {
        try (
                Response response = client.newCall(new Request.Builder()
                                                           .url(authority + "/.well-known/openid-configuration")
                                                           .get()
                                                           .build())
                        .execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException(
                        "OIDC discovery failed, HTTP " + response.code()
                );
            }
            ResponseBody body = response.body();
            if (body == null) {
                throw new RuntimeException("OIDC discovery returned empty body");
            }
            openidConfiguration = objectMapper.readValue(body.string(), OpenidConfiguration.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load OIDC endpoints", e);
        }
    }

    private String generateCodeVerifier() {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(random);
    }

    private String generateCodeChallenge(String verifier) {
        byte[] digest = messageDigest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(digest);
    }

    private TokenResponse waitForAuthorizationCode(String codeVerifier) throws IOException, InterruptedException, URISyntaxException {
        CountDownLatch latch = new CountDownLatch(1);
        final TokenResponse[] resultHolder = new TokenResponse[1];

        HttpServer server = HttpServer.create(new InetSocketAddress(redirectUri.getPort()), 0);
        server.createContext(
                "/callback", (HttpExchange exchange) -> {
                    String query = exchange.getRequestURI()
                            .getQuery();
                    if (query != null && query.contains("code=")) {
                        resultHolder[0] = exchangeCodeForToken(codeVerifier, extractCode(query));
                        String response = objectMapper.writeValueAsString(resultHolder[0]);
                        exchange.sendResponseHeaders(200, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                        exchange.getResponseBody().close();
                        latch.countDown();
                    } else if (query != null && query.contains("error=")) {
                        String response = "Error during authorization: " + query;
                        exchange.sendResponseHeaders(400, response.length());
                        exchange.getResponseBody()
                                .write(response.getBytes());
                        exchange.getResponseBody()
                                .close();
                        latch.countDown();
                    }
                });
        server.start();

        URI uri = new URI(openidConfiguration.authorizationEndpoint() + "?" +
                                  "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                                  "&response_type=code" +
                                  "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8) +
                                  "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8) +
                                  "&code_challenge=" + URLEncoder.encode(
                generateCodeChallenge(codeVerifier),
                StandardCharsets.UTF_8) +
                                  "&code_challenge_method=S256");
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop()
                    .browse(uri);
        } else {
            System.out.println("Open this URL and login in: ");
            System.out.println(uri);
        }

        if (!latch.await(5, TimeUnit.MINUTES)) {
            throw new RuntimeException("Authorization code not received in 5 minutes");
        }
        server.stop(0);
        return resultHolder[0];
    }

    private TokenResponse exchangeCodeForToken(String codeVerifier, final String authorizationCode) throws IOException {
        try (
                Response response = client.newCall(new Request.Builder()
                                                           .url(openidConfiguration.tokenEndpoint())
                                                           .post(new FormBody.Builder()
                                                                         .add("client_id", clientId)
                                                                         .add("grant_type", "authorization_code")
                                                                         .add("code", authorizationCode)
                                                                         .add("redirect_uri", redirectUri.toString())
                                                                         .add("scope", scope)
                                                                         .add("code_verifier", codeVerifier)
                                                                         .build())
                                                           .header("Accept", "application/json")
                                                           .build())
                        .execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException("Token request failed: " + response);
            }
            assert response.body() != null;
            return objectMapper.readValue(
                    response.body()
                            .string(), TokenResponse.class);
        }
    }

    private String extractCode(String query) {
        for (String param : query.split("&")) {
            String[] kv = param.split("=");
            if (kv.length == 2 && kv[0].equals("code")) {
                return kv[1];
            }
        }
        return null;
    }
}