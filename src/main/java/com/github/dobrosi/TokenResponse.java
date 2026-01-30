package com.github.dobrosi;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record TokenResponse(
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("id_token")
        String idToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        Long expiresIn,

        @JsonProperty("ext_expires_in")
        Long extExpiresIn,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("refresh_expires_in")
        Long refreshExpiresIn,

        @JsonProperty("scope")
        String scope
) {
}