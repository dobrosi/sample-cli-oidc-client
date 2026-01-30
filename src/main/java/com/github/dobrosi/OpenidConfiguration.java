package com.github.dobrosi;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record OpenidConfiguration (
        @JsonProperty("authorization_endpoint")
        String authorizationEndpoint,

        @JsonProperty("token_endpoint")
        String tokenEndpoint
) {}