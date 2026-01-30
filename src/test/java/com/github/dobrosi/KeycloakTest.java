package com.github.dobrosi;

public class KeycloakTest {

    private static final String AUTHORITY = "http://localhost:8080/realms/microsec";
    private static final String CLIENT_ID = "test-cli-app";
    private static final String REDIRECT_URI = "http://localhost:8888/callback";
    private static final String SCOPE = "openid profile email";

    private static final OidcClient oidcClient = new OidcClient(AUTHORITY, CLIENT_ID, REDIRECT_URI, SCOPE);

    public static void main(String[] args) {
        System.out.println(oidcClient.authorize());
    }
}
