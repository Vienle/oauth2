package com.social.oauth2.security.oauth2;

import com.social.oauth2.modal.oauth2.AuthProvider;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.social.oauth2.constant.Oauth2Constant.ZALO_REFRESH_TOKEN_EXPIRES_IN;

public class CustomTokenResponseConverter implements
    Converter<Map<String, Object>, OAuth2AccessTokenResponse> {

    private final ClientRegistrationRepository clientRegistrationRepository;

    public CustomTokenResponseConverter(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public OAuth2AccessTokenResponse convert(Map<String, Object> tokenResponseParameters) {
        String accessToken = tokenResponseParameters.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        String refreshToken = tokenResponseParameters.get(OAuth2ParameterNames.REFRESH_TOKEN).toString();
        String expiresIn = tokenResponseParameters.get(OAuth2ParameterNames.EXPIRES_IN).toString();
        OAuth2AccessToken.TokenType accessTokenType = OAuth2AccessToken.TokenType.BEARER;

        Map<String, Object> additionalRefreshTokenAttribute = new HashMap<>();
        // add refresh token expire with zalo provide
        if (!Objects.isNull(clientRegistrationRepository.findByRegistrationId(AuthProvider.zalo.name()))){
            String refreshTokenExpiresIn = tokenResponseParameters.get(ZALO_REFRESH_TOKEN_EXPIRES_IN).toString();
            additionalRefreshTokenAttribute.put(ZALO_REFRESH_TOKEN_EXPIRES_IN,Long.parseLong(refreshTokenExpiresIn));
        }
        additionalRefreshTokenAttribute.put(OAuth2ParameterNames.REFRESH_TOKEN,refreshToken);

        Set<String> scopes = Collections.emptySet();
        if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            String scope = tokenResponseParameters.get(OAuth2ParameterNames.SCOPE).toString();
            scopes = Arrays.stream(StringUtils.delimitedListToStringArray(scope, ","))
                .collect(Collectors.toSet());
        }

        return OAuth2AccessTokenResponse.withToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(Long.parseLong(expiresIn))
            .additionalParameters(additionalRefreshTokenAttribute)
            .tokenType(accessTokenType)
            .scopes(scopes)
            .build();
    }
}
