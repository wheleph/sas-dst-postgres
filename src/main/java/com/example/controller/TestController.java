package com.example.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    private static final Logger log = LoggerFactory.getLogger(TestController.class);

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper;

    public TestController(
        OAuth2AuthorizationService authorizationService,
        RegisteredClientRepository registeredClientRepository,
        ObjectMapper objectMapper
    ) {
        this.authorizationService = authorizationService;
        this.registeredClientRepository = registeredClientRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/store-and-read")
    public String storeAndReadToken() {
        var registeredClient = registeredClientRepository.findByClientId("client");

        var oauth2AuthorizationId = UUID.randomUUID().toString();
        var issuedAt = Instant.parse("2025-10-26T00:50:00Z"); // 10-minutes before DST switch
        var expiresAt = issuedAt.plus(Duration.ofMinutes(30));
        var oauth2Authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .id(oauth2AuthorizationId)
            .principalName("foobar-principal")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .accessToken(new OAuth2AccessToken(TokenType.BEARER, "foobar-token", issuedAt, expiresAt))
            .build();
        authorizationService.save(oauth2Authorization);

        try {
            var fetchedOAuth2Authorization = authorizationService.findById(oauth2AuthorizationId);
            return objectMapper.writeValueAsString(fetchedOAuth2Authorization);
        } catch (Exception e) {
            log.error("Error when find oauth2 authorization with id {}", oauth2AuthorizationId, e);
            return "{ \"Error\": \"" + oauth2AuthorizationId + "\"}";
        }
    }
}
