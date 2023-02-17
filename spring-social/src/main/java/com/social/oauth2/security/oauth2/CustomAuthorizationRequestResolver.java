package com.social.oauth2.security.oauth2;

import com.social.oauth2.constant.Oauth2Constant;
import com.social.oauth2.modal.oauth2.AuthProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Objects;

/**
 * Add or change params when call authorize request
 * Late received code from callback from provide, We use it call api get refresh Token
 */
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorize";

    private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;
    private final ClientRegistrationRepository clientRegistrationRepository;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        this.defaultAuthorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, AUTHORIZATION_REQUEST_BASE_URI);
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest =
            this.defaultAuthorizationRequestResolver.resolve(request);

        return authorizationRequest != null ?
            customAuthorizationRequest(authorizationRequest) :
            null;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest =
            this.defaultAuthorizationRequestResolver.resolve(
                request, clientRegistrationId);

        return authorizationRequest != null ?
            customAuthorizationRequest(authorizationRequest) :
            null;
    }

    private OAuth2AuthorizationRequest customAuthorizationRequest(
        OAuth2AuthorizationRequest authorizationRequest) {

        if (Objects.isNull(clientRegistrationRepository.findByRegistrationId(AuthProvider.zalo.name()))) {
            return authorizationRequest;
        }

        /*
         * By defaul Oauth2 use param name client_id call api get code
         * But Zalo use param name app_id call api get code
         * change client_id to app_id when AuthProvider is Zalo
         */
        String customAuthorizationRequestUri = UriComponentsBuilder
            .fromUriString(authorizationRequest.getAuthorizationRequestUri().replace("client_id", Oauth2Constant.ZALO_PARAM_APP_ID))
            .build(true)
            .toUriString();

        return OAuth2AuthorizationRequest.from(authorizationRequest)
            .authorizationRequestUri(customAuthorizationRequestUri)
            .build();
    }
}
