package com.social.oauth2.security.oauth2;

import com.social.oauth2.modal.oauth2.AuthProvider;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;

import java.util.Collections;
import java.util.Iterator;
import java.util.Objects;

public class CustomOAuth2UserRequestEntityConverter implements
    Converter<OAuth2UserRequest, RequestEntity<?>> {
    private final String ACCESS_TOKEN = "access_token";
    private OAuth2UserRequestEntityConverter defaultConverter;

    public CustomOAuth2UserRequestEntityConverter() {
        defaultConverter = new OAuth2UserRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2UserRequest req) {
        ClientRegistration clientRegistration = req.getClientRegistration();
        RequestEntity<?> entity = defaultConverter.convert(req);

        if (req == null) {
            return entity;
        }
        String registrationId = clientRegistration.getRegistrationId();
        if (registrationId.equalsIgnoreCase(AuthProvider.zalo.name())) {
            // add new field in header
            MultiValueMap<String, String> newHeaders = new LinkedMultiValueMap<>();
            if (!Objects.isNull(entity) && !Objects.isNull(entity.getHeaders())){
                MultiValueMap<String, String> currentHeaders = entity.getHeaders();
                Iterator<String> it = currentHeaders.keySet().iterator();
                while (it.hasNext()) {
                    String theKey = (String) it.next();
                    newHeaders.put(theKey, Collections.singletonList(currentHeaders.getFirst(theKey)));
                }
            }
            newHeaders.add(ACCESS_TOKEN, req.getAccessToken().getTokenValue());
//            newHeaders.set("Accept", "text/json;charset=UTF-8");

            return new RequestEntity<>(newHeaders,
                entity.getMethod(), entity.getUrl());
        }

        return null;
    }
}