/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.wso2.carbon.identity.outbound.organization.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.MisconfigurationException;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants;

import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.outbound.organization.auth.utils.OIDCTokenValidationUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.KAKAO_AUTH_URL;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.KAKAO_OAUTH2_STATE_SUFFIX;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.REDIRECT_URL;
import static org.wso2.carbon.identity.outbound.organization.auth.utils.OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.utils.OIDCAuthenticatorConstants.ID_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE;


/***
 * Organization Authenticator is an outbound authenticator implementation for social login provider named Organization
 * This extends Oauth Generic Authenticator implementation
 */
public class OrganizationAuthenticator extends Oauth2GenericAuthenticator {

    private static final long serialVersionUID = 6614257960044886319L;

    /**
     * Check whether the request can be handled by the authenticator.
     *
     * @param request The http servlet request
     * @return true if the request can be handled by the authenticator.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isNativeSDKBasedFederationCall(request) || super.canHandle(request);
    }

    @Override
    public String getFriendlyName() {

        return OrganizationAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return OrganizationAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return OrganizationAuthenticatorConstants.KAKAO_TOKEN_URL;
    }

    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return KAKAO_AUTH_URL;
    }

    @Override
    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return OrganizationAuthenticatorConstants.KAKAO_INFO_URL;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback url");
        configProperties.add(callbackUrl);

        return configProperties;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        super.initiateAuthenticationRequest(request, response, context);
        String clientId = context.getAuthenticatorProperties().get(CLIENT_ID);
        String state = context.getContextIdentifier() + KAKAO_OAUTH2_STATE_SUFFIX;
        String redirectUri = context.getAuthenticatorProperties().get(CALLBACK_URL);
        context.setProperty(OAUTH2_PARAM_STATE, state);
        String redirectUrl = KAKAO_AUTH_URL +
                "?response_type=code" +
                "&client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&state=" + state;
        context.setProperty(REDIRECT_URL, redirectUrl);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String token;
            if (isNativeSDKBasedFederationCall(request)) {
                token = request.getParameter(ACCESS_TOKEN_PARAM);
                String idToken = request.getParameter(ID_TOKEN_PARAM);
                if (StringUtils.isNotBlank(idToken)) {
                    validateJWTToken(context, idToken);
                }
            } else {
                String clientId = authenticatorProperties.get(CLIENT_ID);
                String clientSecret = authenticatorProperties.get(CLIENT_SECRET);
                String redirectUri = authenticatorProperties.get(CALLBACK_URL);
                Boolean basicAuthEnabled = Boolean.parseBoolean(authenticatorProperties
                        .get(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED));
                String code = getAuthorizationCode(request);
                String tokenEP = getTokenEndpoint(authenticatorProperties);
                token = getToken(tokenEP, clientId, clientSecret, code, redirectUri, basicAuthEnabled);
            }

            Boolean selfContainedTokenEnabled = Boolean.parseBoolean(authenticatorProperties
                    .get(Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED));
            String userInfo = getUserInfo(selfContainedTokenEnabled, token, authenticatorProperties);
            buildClaims(context, userInfo);
        } catch (ApplicationAuthenticatorException | MisconfigurationException e) {
            String errorMessage = "Error while processing authentication response.";
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private boolean isNativeSDKBasedFederationCall(HttpServletRequest request) {

        return request.getParameter(ACCESS_TOKEN_PARAM) != null && request.getParameter(ID_TOKEN_PARAM) != null;
    }
    private void validateJWTToken(AuthenticationContext context, String idToken) throws AuthenticationFailedException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            validateAudience(context, claimsSet.getAudience());
            OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
            String tenantDomain = context.getTenantDomain();
            String idpIdentifier = OIDCTokenValidationUtil.getIssuer(claimsSet);
            IdentityProvider identityProvider = getIdentityProvider(idpIdentifier, tenantDomain);

            OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
        } catch (ParseException | JOSEException | IdentityProviderManagementException | IdentityOAuth2Exception e) {
            throw new AuthenticationFailedException(OrganizationAuthenticatorConstants.ErrorMessages.
                    JWT_TOKEN_VALIDATION_FAILED.getMessage(), e);
        }
    }

    private void validateAudience(AuthenticationContext context, List<String> audience)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(CLIENT_ID);
        if (audience == null || !audience.contains(clientId)) {
            throw new AuthenticationFailedException(
                    OrganizationAuthenticatorConstants.ErrorMessages.ID_TOKEN_AUD_VALIDATION_FAILED.getMessage());
        }
    }

    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws IdentityProviderManagementException {

        IdentityProvider identityProvider;
        identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

        if (identityProvider == null) {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
        }

        return identityProvider;
    }
}
