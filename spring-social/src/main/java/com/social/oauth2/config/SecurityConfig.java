package com.social.oauth2.config;


import com.social.oauth2.modal.oauth2.CustomRequestEntityConverter;
import com.social.oauth2.modal.oauth2.CustomTokenResponseConverter;
import com.social.oauth2.security.RestAuthenticationEntryPoint;
import com.social.oauth2.security.TokenAuthenticationFilter;
import com.social.oauth2.security.oauth2.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.MimeType;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@Configuration
public class SecurityConfig {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final TokenAuthenticationFilter tokenAuthenticationFilter;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
                          HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository,
                          CustomOAuth2UserService customOAuth2UserService,
                          OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                          OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler,
                          TokenAuthenticationFilter tokenAuthenticationFilter) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
        this.customOAuth2UserService = customOAuth2UserService;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
        this.tokenAuthenticationFilter = tokenAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .formLogin()
            .disable()
            .httpBasic()
            .disable()
            .exceptionHandling()
            .authenticationEntryPoint(new RestAuthenticationEntryPoint())
            .and()
            .authorizeHttpRequests((authz) -> {
                authz
                    .requestMatchers("/public/**", "/auth/**", "/oauth2/**", "/login/oauth2/code/*", "/login/oauth2/**")
                    //                .requestMatchers(antMatcher("/public/**"),antMatcher("/oauth2/**"),antMatcher("/auth/**"))
                    .permitAll()
                    .anyRequest()
                    .authenticated();
            })
            .oauth2Login()
            .authorizationEndpoint()
            .authorizationRequestResolver(
                new CustomAuthorizationRequestResolver(
                    this.clientRegistrationRepository))
            .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
            .and()
            .tokenEndpoint()
            .accessTokenResponseClient(this.accessTokenResponseClient())
            .and()
            .userInfoEndpoint()
            .userService(customOAuth2UserService)
            .and()
            .successHandler(oAuth2AuthenticationSuccessHandler)
            .failureHandler(oAuth2AuthenticationFailureHandler)
            .and()
            .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
}

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
            new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRequestEntityConverter(new CustomRequestEntityConverter());

        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();
        tokenResponseHttpMessageConverter.setAccessTokenResponseConverter(new CustomTokenResponseConverter());
        List<MediaType> currentSupportMediaType = tokenResponseHttpMessageConverter.getSupportedMediaTypes();

        List<MediaType> customMediaType = new ArrayList<>();
        for (MediaType mediaType : currentSupportMediaType) {
            customMediaType.add(mediaType);
        }
        MediaType addNewMediaType = new MediaType(new MimeType("text", "json", Charset.forName("UTF-8")));
        customMediaType.add(addNewMediaType);
        tokenResponseHttpMessageConverter.setSupportedMediaTypes(customMediaType);
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
            new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

        accessTokenResponseClient.setRestOperations(restTemplate);
        return accessTokenResponseClient;
    }

}
