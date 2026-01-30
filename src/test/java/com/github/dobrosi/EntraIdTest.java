package com.github.dobrosi;

public class EntraIdTest {
    private static final String TENANT_ID = "52cef3bf-e5af-4b1c-8882-368d2a2933d5";
    private static final String AUTHORITY = "https://login.microsoftonline.com/" + TENANT_ID + "/v2.0";
    private static final String CLIENT_ID = "8e17364c-99f1-44de-ac09-a30885493d0d";
    private static final String REDIRECT_URI = "http://localhost:8888/callback";
    private static final String SCOPE = "openid profile api://8e17364c-99f1-44de-ac09-a30885493d0d/myapi";

    private static final OidcClient oidcClient = new OidcClient(AUTHORITY, CLIENT_ID, REDIRECT_URI, SCOPE);

    public static void main(String[] args) {
        System.out.println(oidcClient.authorize());
    }
}