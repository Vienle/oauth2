package com.social.oauth2.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/public")
public class PublicTestController {

    @GetMapping
    public ResponseEntity<Object> publicTestSecurity(){
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/vien")
    public ResponseEntity<Object> publicTestSecurityVien(){
        return ResponseEntity.ok("Vien");
    }
}
