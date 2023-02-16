package com.social.oauth2.security.oauth2.user;

import java.util.LinkedHashMap;
import java.util.Map;

public class ZaloOauth2UserInfo extends OAuth2UserInfo{
    public ZaloOauth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }
    @Override
    public String getId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getName() {
        return attributes.get("name").toString();
    }

    @Override
    public String getEmail() {
        return  attributes.get("id").toString().concat("_zalo@gmail.com");
    }

    @Override
    public String getImageUrl() {
        LinkedHashMap<String,Object> getPicture = (LinkedHashMap<String, Object>) attributes.get("picture");
        if (getPicture.isEmpty()){
            return null;
        }
        LinkedHashMap<String,Object> getDataUrl = (LinkedHashMap<String, Object>) getPicture.get("data");
        if (getDataUrl.isEmpty()){
            return null;
        }
        return getDataUrl.get("url").toString();

    }
}
