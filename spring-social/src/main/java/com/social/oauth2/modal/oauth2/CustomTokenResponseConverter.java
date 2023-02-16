package com.social.oauth2.modal.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CustomTokenResponseConverter implements
    Converter<Map<String, Object>, OAuth2AccessTokenResponse> {
    private static final Set<String> TOKEN_RESPONSE_PARAMETER_NAMES = Stream.of(
        OAuth2ParameterNames.ACCESS_TOKEN,
        OAuth2ParameterNames.TOKEN_TYPE,
        OAuth2ParameterNames.EXPIRES_IN,
        OAuth2ParameterNames.REFRESH_TOKEN,
        OAuth2ParameterNames.SCOPE).collect(Collectors.toSet());


    @Override
    public OAuth2AccessTokenResponse convert(Map<String, Object> tokenResponseParameters) {
        String accessToken = tokenResponseParameters.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        String refreshToken = tokenResponseParameters.get(OAuth2ParameterNames.REFRESH_TOKEN).toString();
        String expiresIn = tokenResponseParameters.get(OAuth2ParameterNames.EXPIRES_IN).toString();
        String refreshTokenExpiresIn = tokenResponseParameters.get("refresh_token_expires_in").toString();
        OAuth2AccessToken.TokenType accessTokenType = OAuth2AccessToken.TokenType.BEARER;

        Map<String,Object> additionalRefreshTokenExpiresIn = new HashMap<>();
        additionalRefreshTokenExpiresIn.put("refresh_token_expires_in",Long.parseLong(refreshTokenExpiresIn));

        Set<String> scopes = Collections.emptySet();
        if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            String scope = tokenResponseParameters.get(OAuth2ParameterNames.SCOPE).toString();
            scopes = Arrays.stream(StringUtils.delimitedListToStringArray(scope, ","))
                .collect(Collectors.toSet());
        }

        return OAuth2AccessTokenResponse.withToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(Long.parseLong(expiresIn))
            .additionalParameters(additionalRefreshTokenExpiresIn)
            .tokenType(accessTokenType)
            .scopes(scopes)
            .build();
    }
}
