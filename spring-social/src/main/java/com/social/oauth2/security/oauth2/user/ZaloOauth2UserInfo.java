package com.social.oauth2.security.oauth2.user;

import java.util.Map;

public class ZaloOauth2UserInfo extends OAuth2UserInfo{
    public ZaloOauth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }
    @Override
    public String getId() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public String getEmail() {
        return null;
    }

    @Override
    public String getImageUrl() {
        return null;
    }
}
