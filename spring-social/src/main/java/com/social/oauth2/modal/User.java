package com.social.oauth2.modal;

import com.social.oauth2.modal.oauth2.AuthProvider;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;
    private String imageUrl;
    private Boolean emailVerified = false;
    private String password;
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;
    private String providerId;
    private String accessToken;
    private String refreshToken;
    @Column(name = "expires_time")
    private LocalDateTime expiresTime;
    @Column(name = "expires_refresh_time")
    private LocalDateTime expiresRefreshTime;
}
