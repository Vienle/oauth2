package com.social.oauth2.security.oauth2;

import com.social.oauth2.constant.Oauth2Constant;
import com.social.oauth2.exception.OAuth2AuthenticationProcessingException;
import com.social.oauth2.modal.User;
import com.social.oauth2.modal.oauth2.AuthProvider;
import com.social.oauth2.repository.UserRepository;
import com.social.oauth2.security.CustomUserService;
import com.social.oauth2.security.UserPrincipal;
import com.social.oauth2.security.oauth2.user.OAuth2UserInfo;
import com.social.oauth2.security.oauth2.user.OAuth2UserInfoFactory;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.TimeZone;

/**
 * Handle user to database
 */
@Service
@AllArgsConstructor
public class CustomOAuth2UserService extends CustomUserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {

        String providerId = oAuth2UserRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerId, oAuth2User.getAttributes());

        if (!providerId.equals(AuthProvider.zalo.toString()) && StringUtils.isNotEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
            if (!user.getProvider().equals(AuthProvider.valueOf(providerId))) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " + user.getProvider() + " account. Please use your " + user.getProvider() + " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo, oAuth2UserRequest);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }
        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {

        LocalDateTime expiresToken = LocalDateTime.ofInstant(oAuth2UserRequest.getAccessToken().getExpiresAt(), ZoneId.of("UTC"));
        LocalDateTime expiresRefreshToken = expiresToken.plusSeconds(Long.parseLong(oAuth2UserRequest.getAdditionalParameters().get(Oauth2Constant.ZALO_REFRESH_TOKEN_EXPIRES_IN).toString()));

        User user = new User();
        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        // zalo id type is String
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setProviderId(String.valueOf(oAuth2UserInfo.getId()));
        user.setName(oAuth2UserInfo.getName());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());
        user.setAccessToken(oAuth2UserRequest.getAccessToken().getTokenValue());
        user.setRefreshToken(oAuth2UserRequest.getAdditionalParameters().get(OAuth2ParameterNames.REFRESH_TOKEN).toString());
        user.setExpiresTime(expiresToken);
        user.setExpiresRefreshTime(expiresRefreshToken);
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo, OAuth2UserRequest oAuth2UserRequest) {

        LocalDateTime expiresToken = LocalDateTime.ofInstant(oAuth2UserRequest.getAccessToken().getExpiresAt(), ZoneId.of("UTC"));
        LocalDateTime expiresRefreshToken = expiresToken.plusSeconds(Long.parseLong(oAuth2UserRequest.getAdditionalParameters().get(Oauth2Constant.ZALO_REFRESH_TOKEN_EXPIRES_IN).toString()));
        existingUser.setAccessToken(oAuth2UserRequest.getAccessToken().getTokenValue());
        existingUser.setRefreshToken(oAuth2UserRequest.getAdditionalParameters().get(OAuth2ParameterNames.REFRESH_TOKEN).toString());
        existingUser.setExpiresTime(expiresToken);
        existingUser.setExpiresRefreshTime(expiresRefreshToken);

        existingUser.setName(oAuth2UserInfo.getName());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        existingUser.setAccessToken(oAuth2UserRequest.getAccessToken().getTokenValue());
        existingUser.setRefreshToken(oAuth2UserRequest.getAdditionalParameters().get(OAuth2ParameterNames.REFRESH_TOKEN).toString());
        return userRepository.save(existingUser);
    }

}
