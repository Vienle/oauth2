package com.social.oauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/public")
public class PublicTestController {

    @GetMapping
    public ResponseEntity<Object> publicTestSecurity(
    ) {
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/vien")
    public ResponseEntity<Object> publicTestSecurityVien() {
        return ResponseEntity.ok("Vien");
    }
}
