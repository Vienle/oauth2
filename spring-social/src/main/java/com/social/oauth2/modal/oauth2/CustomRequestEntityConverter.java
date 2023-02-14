package com.social.oauth2.modal.oauth2;

import com.social.oauth2.constant.Oauth2Constant;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.Iterator;

public class CustomRequestEntityConverter implements
    Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    private final String ZALO_SECRET_KEY = "secret_key";
    private final String ZALO_HEADER_ACCEPT = "Accept";
    private final String ZALO_HEADER_MEDIA_TYPE_TEXT_JSON = "text/json;charset=UTF-8";
    private OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter;

    public CustomRequestEntityConverter() {
        defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest req) {
        ClientRegistration clientRegistration = req.getClientRegistration();
        RequestEntity<?> entity = defaultConverter.convert(req);

        if (req == null){
            return entity;
        }
        String registrationId = clientRegistration.getRegistrationId();
        if (registrationId.equalsIgnoreCase(AuthProvider.zalo.name())){
            // add new field in header
            MultiValueMap<String, String> currentHeaders = entity.getHeaders();
            Iterator<String> it = currentHeaders.keySet().iterator();
            MultiValueMap<String, String> newHeaders = new LinkedMultiValueMap<>();
            while(it.hasNext()){
                String theKey = (String)it.next();
                newHeaders.put(theKey, Collections.singletonList(currentHeaders.getFirst(theKey)));
            }
            newHeaders.add(ZALO_SECRET_KEY, clientRegistration.getClientSecret());
            newHeaders.set(ZALO_HEADER_ACCEPT, ZALO_HEADER_MEDIA_TYPE_TEXT_JSON);
            entity.getHeaders();

            // add new filed in body
            MultiValueMap<String, String> params = (MultiValueMap<String,String>) entity.getBody();
            params.add(Oauth2Constant.ZALO_PARAM_APP_ID, clientRegistration.getClientId());
            return new RequestEntity<>(params, newHeaders,
                entity.getMethod(), entity.getUrl());
        }

        return null;
    }

}
