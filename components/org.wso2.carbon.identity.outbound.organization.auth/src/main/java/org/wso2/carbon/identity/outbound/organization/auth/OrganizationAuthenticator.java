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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.MisconfigurationException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.outbound.organization.auth.internal.OrganizationAuthDataHolder;
import org.wso2.carbon.identity.outbound.organization.auth.utils.TenantServiceProviderUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL;

import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.AMPERSAND_SIGN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.AUTHENTICATOR_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.CODE_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.COMMON_SP_NAME;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.CONTEXT_RESOLVED_CLIENT_ID;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.CONTEXT_RESOLVED_CLIENT_SECRET;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.CONTEXT_TENANT_DOMAIN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.EQUAL_SIGN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.IDP_PARAMETER;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.IS_AUTHORIZE_EP_PATTERN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.IS_BASE_URL_PROP;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.IS_TOKEN_EP_PATTERN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.IS_USERINFO_EP_PATTERN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.OAUTH2_STATE_SUFFIX;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.SCOPE;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.SESSION_DATA_KEY_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.TENANT_DOMAIN_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.TENANT_IDENTIFIER;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.TENANT_SELECTION_URL_PROP;
import static org.wso2.carbon.identity.outbound.organization.auth.utils.OIDCAuthenticatorConstants.USERINFO_URL;

/**
 * Organization Authenticator is a federated outbound authenticator that implements
 * tenant-aware SSO for the WSO2 API Manager Publisher portal.
 * <p>
 * The authenticator implements a 3-step flow:
 * <ol>
 *   <li>Step 1 (Initial): Redirect to tenant selection page.</li>
 *   <li>Step 2 (Tenant received): Resolve tenant app client_id and redirect to IS /t/{tenant}/oauth2/authorize.</li>
 *   <li>Step 3 (Auth code received): Exchange code for token, get user info, build claims.</li>
 * </ol>
 * This extends the Oauth2 Generic Authenticator implementation.
 */
public class OrganizationAuthenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = 6614257960044886319L;
    private static final Log log = LogFactory.getLog(OrganizationAuthenticator.class);


    @Override
    public boolean canHandle(HttpServletRequest request) {

        // Handle logout requests in the super class.
        if (super.canHandle(request)) {
            return true;
        }

        // Handle the tenant selection response with the tenant identifier parameter.
        String tenantIdentifier = request.getParameter(TENANT_IDENTIFIER);
        return StringUtils.isNotBlank(tenantIdentifier);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {

            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            ApplicationManagementService appMgtService =
                    OrganizationAuthDataHolder.getInstance().getApplicationManagementService();

            // Retrieve tenant-specific values stored during step 2.
            String tenantDomain = (String) context.getProperty(TENANT_DOMAIN_PARAM);
            String spName = authenticatorProperties.get(COMMON_SP_NAME);

            // Resolve the OAuth2 client ID for the tenant's common SP.
            String resolvedClientId = null;
            resolvedClientId = TenantServiceProviderUtil.resolveClientId(appMgtService, tenantDomain, spName);

            OAuthConsumerAppDTO oauthApp = getOAuthAdminService()
                    .getOAuthApplicationData(resolvedClientId);

            String resolvedClientSecret = oauthApp.getOauthConsumerSecret();

            // Override authenticator properties with tenant-specific values so
            // the super class uses the correct client_id and endpoints.
            String isBaseUrl = authenticatorProperties.get(IS_BASE_URL_PROP);
            authenticatorProperties.put(CLIENT_ID, resolvedClientId);
            authenticatorProperties.put(CLIENT_SECRET, resolvedClientSecret);
            authenticatorProperties.put(OAUTH2_AUTHZ_URL, isBaseUrl + String.format(IS_AUTHORIZE_EP_PATTERN, tenantDomain));
            authenticatorProperties.put(USERINFO_URL,
                    isBaseUrl + String.format(IS_USERINFO_EP_PATTERN, tenantDomain));
            authenticatorProperties.put(OAUTH2_TOKEN_URL, isBaseUrl + String.format(IS_TOKEN_EP_PATTERN, tenantDomain));
            authenticatorProperties.put(CALLBACK_URL, oauthApp.getCallbackUrl());


            super.initiateAuthenticationRequest(request, response, context);
        } catch (Exception e) {
            String errorMessage = "Error while initiating authentication request.";
            throw new AuthenticationFailedException(errorMessage, e);
        }

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
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property commonSpName = new Property();
        commonSpName.setName(COMMON_SP_NAME);
        commonSpName.setDisplayName("Common Service Provider Name");
        commonSpName.setRequired(true);
        commonSpName.setDescription("Enter common service provider name registered in each tenant (e.g., PublisherCommonSP)");
        configProperties.add(commonSpName);

        Property callbackUrl = new Property();
        callbackUrl.setName(CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback URL (e.g., https://localhost:9443/commonauth)");
        configProperties.add(callbackUrl);

        Property isBaseUrl = new Property();
        isBaseUrl.setName(IS_BASE_URL_PROP);
        isBaseUrl.setDisplayName("Identity Server Base URL");
        isBaseUrl.setRequired(true);
        isBaseUrl.setDescription("Enter IS base URL (e.g., https://localhost:9443)");
        configProperties.add(isBaseUrl);

        Property tenantSelectionUrl = new Property();
        tenantSelectionUrl.setName(TENANT_SELECTION_URL_PROP);
        tenantSelectionUrl.setDisplayName("Tenant Selection Page URL");
        tenantSelectionUrl.setRequired(true);
        tenantSelectionUrl.setDescription(
                "Enter tenant selection page URL (e.g., https://localhost:9443/select-tenant)");
        configProperties.add(tenantSelectionUrl);

        return configProperties;
    }

    /**
     * Main entry point — implements the 3-step authentication flow.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {

        // Handle logout.
        if (context.isLogoutRequest()) {
            return super.process(request, response, context);
        }

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        try {

            // ──── STEP 2: Tenant domain received from tenant selection page ────
            String tenantIdentifier = request.getParameter(TENANT_IDENTIFIER);
            if (!StringUtils.isNotBlank(tenantIdentifier)) {
                handleTenantSelection(response, context, authenticatorProperties);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
            context.setProperty(TENANT_DOMAIN_PARAM, tenantIdentifier);
            return super.process(request, response, context);

        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    OrganizationAuthenticatorConstants.ErrorMessages.TENANT_REDIRECT_FAILED.getMessage(), e);
        }
    }

    /**
     * Step 1: Redirect to the tenant selection page with the sessionDataKey.
     */
    private void handleTenantSelection(HttpServletResponse response,
                                                          AuthenticationContext context,
                                                          Map<String, String> authenticatorProperties)
            throws IOException {

        String tenantSelectionUrl = authenticatorProperties.get(TENANT_SELECTION_URL_PROP);
        String sessionDataKey = context.getContextIdentifier();

        String redirectUrl = tenantSelectionUrl + "?" + SESSION_DATA_KEY_PARAM + "=" + sessionDataKey
                + "&" + AUTHENTICATOR_PARAM + "=" + getName()
                + "&" + IDP_PARAMETER + "=" + context.getExternalIdP().getIdPName();

        if (log.isDebugEnabled()) {
            log.debug("Redirecting to tenant selection page: " + redirectUrl);
        }
        response.sendRedirect(redirectUrl);
    }

//    /**
//     * Step 2: Resolve the client_id for the tenant and redirect to IS /t/{tenant}/oauth2/authorize.
//     */
//    private AuthenticatorFlowStatus handleTenantRedirect(HttpServletRequest request, HttpServletResponse response,
//                                                         AuthenticationContext context, String tenantDomain,
//                                                         Map<String, String> authenticatorProperties)
//            throws AuthenticationFailedException, IOException {
//
//        // Store tenant domain in context for use in step 3.
//        context.setProperty(CONTEXT_TENANT_DOMAIN, tenantDomain);
//
//        // Resolve the client_id for the tenant's application.
//        String resolvedClientId;
//        try {
//            // Use the default client_id property value as the app name hint for lookup.
//            // The app name in each IS tenant should match this configured value.
//            String appName = authenticatorProperties.get(CLIENT_ID);
//            resolvedClientId = TenantServiceProviderUtil.resolveClientId(tenantDomain, appName);
//        } catch (Exception e) {
//            // Fallback: use the configured client_id if resolution fails.
//            log.warn("Failed to resolve client ID for tenant '" + tenantDomain +
//                    "'. Falling back to configured client_id.", e);
//            resolvedClientId = authenticatorProperties.get(CLIENT_ID);
//        }
//
//        // Store resolved credentials in context for step 3.
//        context.setProperty(CONTEXT_RESOLVED_CLIENT_ID, resolvedClientId);
//        context.setProperty(CONTEXT_RESOLVED_CLIENT_SECRET, authenticatorProperties.get(CLIENT_SECRET));
//
//        // Build the tenant-specific authorize URL.
//        String isBaseUrl = authenticatorProperties.get(IS_BASE_URL_PROP);
//        String authorizeEp = isBaseUrl + String.format(IS_AUTHORIZE_EP_PATTERN, tenantDomain);
//        String callbackUrl = authenticatorProperties.get(CALLBACK_URL);
//        String state = context.getContextIdentifier() + OAUTH2_STATE_SUFFIX;
//
//        String redirectUrl = authorizeEp
//                + "?response_type=code"
//                + "&client_id=" + urlEncode(resolvedClientId)
//                + "&redirect_uri=" + urlEncode(callbackUrl)
//                + "&state=" + urlEncode(state)
//                + "&scope=" + urlEncode(SCOPE);
//
//        if (log.isDebugEnabled()) {
//            log.debug("Redirecting to IS tenant login: " + redirectUrl);
//        }
//        response.sendRedirect(redirectUrl);
//        return AuthenticatorFlowStatus.INCOMPLETE;
//    }

    /**
     * Step 3: Process the authentication response — exchange the authorization code for a token.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            ApplicationManagementService appMgtService =
                    OrganizationAuthDataHolder.getInstance().getApplicationManagementService();

            // Retrieve tenant-specific values stored during step 2.
            String tenantDomain = (String) context.getProperty(TENANT_DOMAIN_PARAM);
            String spName = authenticatorProperties.get(COMMON_SP_NAME);

            // Resolve the OAuth2 client ID for the tenant's common SP.
            String resolvedClientId = TenantServiceProviderUtil.resolveClientId(appMgtService, tenantDomain, spName);

            OAuthConsumerAppDTO oauthApp = getOAuthAdminService()
                    .getOAuthApplicationData(resolvedClientId);

            String resolvedClientSecret = oauthApp.getOauthConsumerSecret();

            // Override authenticator properties with tenant-specific values so
            // the super class uses the correct client_id and endpoints.
            String isBaseUrl = authenticatorProperties.get(IS_BASE_URL_PROP);
            authenticatorProperties.put(CLIENT_ID, resolvedClientId);
            authenticatorProperties.put(CLIENT_SECRET, resolvedClientSecret);
            authenticatorProperties.put(OAUTH2_AUTHZ_URL, isBaseUrl + String.format(IS_AUTHORIZE_EP_PATTERN, tenantDomain));
            authenticatorProperties.put(USERINFO_URL,
                    isBaseUrl + String.format(IS_USERINFO_EP_PATTERN, tenantDomain));
            authenticatorProperties.put(OAUTH2_TOKEN_URL, isBaseUrl + String.format(IS_TOKEN_EP_PATTERN, tenantDomain));
            authenticatorProperties.put(CALLBACK_URL, oauthApp.getCallbackUrl());

            super.processAuthenticationResponse(request, response, context);

            if (log.isDebugEnabled()) {
                log.debug("Resolved client ID '" + resolvedClientId + "' for SP '" + spName +
                        "' in tenant: " + tenantDomain);
            }

            //super.processAuthenticationResponse(request, response, context);

        } catch (ApplicationAuthenticatorException | MisconfigurationException e) {
            String errorMessage = "Error while processing authentication response.";
            throw new AuthenticationFailedException(errorMessage, e);
        } catch (Exception e) {
            String errorMessage = "Error while resolving service provider credentials.";
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * URL-encode a string using UTF-8.
     */
    private String urlEncode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, FrameworkUtils.UTF_8);
    }

    private OAuthAdminServiceImpl getOAuthAdminService() {

        return OrganizationAuthDataHolder.getInstance().getOAuthAdminService();
    }

    private void addQueryParam(StringBuilder builder, String query, String param) throws UnsupportedEncodingException {

        builder.append(AMPERSAND_SIGN).append(query).append(EQUAL_SIGN).append(urlEncode(param));
    }
}
