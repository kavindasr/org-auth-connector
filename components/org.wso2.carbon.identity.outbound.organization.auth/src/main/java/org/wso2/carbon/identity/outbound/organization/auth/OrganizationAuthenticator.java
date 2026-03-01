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
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.Claim;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.outbound.organization.auth.internal.OrganizationAuthDataHolder;
import org.wso2.carbon.identity.outbound.organization.auth.utils.TenantServiceProviderUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.AMPERSAND_SIGN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.AUTHENTICATOR_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.COMMON_SP_NAME;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.EQUAL_SIGN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.IDP_PARAMETER;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.OIDC_CLAIM_DIALECT_URL;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.SESSION_DATA_KEY_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.TENANT_DOMAIN_PARAM;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.TENANT_IDENTIFIER;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.TENANT_SELECTION_URL_PROP;
import static org.wso2.carbon.identity.outbound.organization.auth.utils.OIDCAuthenticatorConstants.USERINFO_URL;

/**
 * Organization Authenticator is a federated outbound authenticator that implements
 * tenant-aware SSO for the WSO2 API Manager Publisher portal.
 * <p>
 * The authenticator implements a multi-step flow:
 * <ol>
 *   <li>Step 1 (Initial): Redirect to tenant selection page.</li>
 *   <li>Step 2 (Tenant received): Resolve tenant app client_id and redirect to
 *       IS /t/{tenant}/oauth2/authorize.</li>
 *   <li>Step 3 (Auth code received): Exchange code for token, get user info, build claims.</li>
 * </ol>
 * This extends the {@link OpenIDConnectAuthenticator} implementation.
 */
public class OrganizationAuthenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = 6614257960044886319L;
    private static final Log LOG = LogFactory.getLog(OrganizationAuthenticator.class);
    private static final String SSO_ADDITIONAL_PARAMS = "ssoAdditionalParams";
    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static final String DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX = "\\$authparam\\{(\\w+)\\}";

    @Override
    public boolean canHandle(HttpServletRequest request) {

        // Handle logout requests via the super class.
        if (super.canHandle(request)) {
            return true;
        }
        // Handle the tenant selection response with the tenant identifier parameter.
        return StringUtils.isNotBlank(request.getParameter(TENANT_IDENTIFIER));
    }

    /**
     * {@inheritDoc}
     * <p>
     * Resolves the tenant-specific OAuth2 credentials and endpoints before delegating
     * to the super class to build and send the authorize redirect.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            overrideTenantAuthenticatorProperties(context);
            super.initiateAuthenticationRequest(request, response, context);
        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error while initiating authentication request.", e);
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
        commonSpName.setDescription(
                "Enter common service provider name registered in each tenant (e.g., PublisherCommonSP)");
        configProperties.add(commonSpName);

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
     * Main entry point — implements the multi-step authentication flow.
     * <p>
     * If no tenant identifier is present, redirects to the tenant selection page.
     * Otherwise stores the tenant domain in the context and delegates to the super class.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {

        if (context.isLogoutRequest()) {
            return super.process(request, response, context);
        }

        try {
            Map<String, String[]> parameterMap = request.getParameterMap();
            if (parameterMap != null && request.getParameterMap().containsKey("code")) {
                // This is the callback from IS with the auth code, proceed with token exchange and user info retrieval.
                return super.process(request, response, context);
                //return AuthenticatorFlowStatus.INCOMPLETE;
            }
            String tenantIdentifier = request.getParameter(TENANT_IDENTIFIER);
            if (StringUtils.isBlank(tenantIdentifier)) {
                redirectToTenantSelectionPage(response, context);
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
     * {@inheritDoc}
     * <p>
     * Resolves tenant-specific OAuth2 credentials and endpoints, then delegates to the
     * super class to exchange the authorization code for tokens and retrieve user info.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            overrideTenantAuthenticatorProperties(context);
            super.processAuthenticationResponse(request, response, context);
            // AuthenticatedUser user =  context.getSubject();
            // if (user != null) {
            //     // 2. Extract or define your username and tenant domain.
            //     // If the subject identifier is in "user@tenantdomain.com" format, you can use WSO2 utilities:
            //     String subjectIdentifier = user.getAuthenticatedSubjectIdentifier();
            //     String tenantDomain = MultitenantUtils.getTenantDomain(subjectIdentifier);
            //     String userName = MultitenantUtils.getTenantAwareUsername(subjectIdentifier);

            //     // Or extract user store domain if it's formatted as "DOMAIN/user"
            //     String userStoreDomain = IdentityUtil.extractDomainFromName(userName);
            //     // String pureUserName = IdentityUtil.extractPureUsername(userName);

            //     // 3. Set the fields on the AuthenticatedUser object
            //     user.setUserName(userName);
            //     user.setTenantDomain(tenantDomain);
            //     user.setUserStoreDomain(userStoreDomain); // Usually good practice to set this as well

            //     // 4. Set the User ID (UUID) if you have it.
            //     // If you need to look it up, you would query the UserStoreManager using the pureUserName and tenant.
            //     // user.setUserId("your-resolved-uuid-here");

            //     // 5. Explicitly set the updated user back into the context
            //     context.setSubject(user);
            // }
        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error while resolving service provider credentials.", e);
        }
    }

    private ClaimMetadataManagementService getClaimManager() {

        return OrganizationAuthDataHolder.getInstance().getClaimMetadataManagementService();
    }

    /**
     * Redirects the user to the tenant selection page, passing the session data key,
     * authenticator name, and IdP name as query parameters.
     *
     * @param response The HTTP response used for the redirect.
     * @param context  The current authentication context.
     * @throws IOException If the redirect fails.
     */
    private void redirectToTenantSelectionPage(HttpServletResponse response, AuthenticationContext context)
            throws IOException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String tenantSelectionUrl = authenticatorProperties.get(TENANT_SELECTION_URL_PROP);
        String sessionDataKey = context.getContextIdentifier();

        String redirectUrl = tenantSelectionUrl
                + "?" + SESSION_DATA_KEY_PARAM + "=" + sessionDataKey
                + "&" + AUTHENTICATOR_PARAM + "=" + getName()
                + "&" + IDP_PARAMETER + "=" + context.getExternalIdP().getIdPName();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Redirecting to tenant selection page: " + redirectUrl);
        }
        response.sendRedirect(redirectUrl);
    }

    /**
     * Resolves the tenant-specific OAuth2 client credentials and endpoint URLs, then
     * overrides the authenticator properties so that the super class operates against
     * the correct tenant.
     * <p>
     * This is invoked by both {@link #initiateAuthenticationRequest} and
     * {@link #processAuthenticationResponse} to ensure consistent configuration.
     *
     * @param context The current authentication context.
     * @throws Exception If the service provider or OAuth app cannot be resolved.
     */
    private void overrideTenantAuthenticatorProperties(AuthenticationContext context) throws Exception {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        ApplicationManagementService appMgtService =
                OrganizationAuthDataHolder.getInstance().getApplicationManagementService();

        String tenantDomain = (String) context.getProperty(TENANT_DOMAIN_PARAM);
        String spName = authenticatorProperties.get(COMMON_SP_NAME);

        ServiceProvider sharedApplication = TenantServiceProviderUtil.getServiceProvider(appMgtService, tenantDomain, spName);

        String resolvedClientId = TenantServiceProviderUtil.resolveClientId(appMgtService, tenantDomain, spName);
        OAuthConsumerAppDTO oauthApp = getOAuthAdminService().getOAuthApplicationData(resolvedClientId);
        String resolvedClientSecret = oauthApp.getOauthConsumerSecret();

        // Get claim mappings from the federated IDP configuration instead of SP's claim config
        ClaimMapping[] claimMappings = getFederatedIdpClaimMappings(sharedApplication, tenantDomain);

        authenticatorProperties.put(CLIENT_ID, resolvedClientId);
        authenticatorProperties.put(CLIENT_SECRET, resolvedClientSecret);
        authenticatorProperties.put(OAUTH2_AUTHZ_URL, "https://localhost:9443/oauth2/authorize");
        authenticatorProperties.put(OAUTH2_TOKEN_URL, "https://localhost:9443/oauth2/token");
        authenticatorProperties.put(USERINFO_URL, "https://localhost:9443/oauth2/userinfo");
        authenticatorProperties.put(FrameworkConstants.QUERY_PARAMS, getQueryParams(context,
                claimMappings, tenantDomain));
        // String queryPrams = context.getQueryParams();
        // String filteredQueryParams = Arrays.stream(queryPrams.split("&"))
        //         .filter(param -> !param.startsWith("client_id="))
        //         .collect(Collectors.joining("&"));
        // authenticatorProperties.put(QUERY_PARAMS,filteredQueryParams);

//        authenticatorProperties.put(OAUTH2_AUTHZ_URL,
//                isBaseUrl + String.format(IS_AUTHORIZE_EP_PATTERN, tenantDomain));
//        authenticatorProperties.put(USERINFO_URL,
//                isBaseUrl + String.format(IS_USERINFO_EP_PATTERN, tenantDomain));
//        authenticatorProperties.put(OAUTH2_TOKEN_URL,
//                isBaseUrl + String.format(IS_TOKEN_EP_PATTERN, tenantDomain));
//        authenticatorProperties.put(CALLBACK_URL, oauthApp.getCallbackUrl());
//        authenticatorProperties.put("callbackUrl", "https://localhost:9443/publisher/services/auth/callback/login");
        authenticatorProperties.put("callbackUrl", "https://localhost:9443/commonauth");


        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolved client ID '" + resolvedClientId + "' for SP '" + spName
                    + "' in tenant: " + tenantDomain);
        }
    }

    /**
     * Retrieves the {@link OAuthAdminServiceImpl} from the data holder.
     *
     * @return The OAuthAdminServiceImpl instance.
     */
    private OAuthAdminServiceImpl getOAuthAdminService() {

        return OrganizationAuthDataHolder.getInstance().getOAuthAdminService();
    }

    /**
     * Constructs the query parameters string to be included in an authorization request.
     *
     * @param context       The authentication context.
     * @param claimMappings An array of claim mappings for attribute extraction.
     * @param tenantDomain  Tenant domain.
     * @return Query parameters string .
     * @throws UnsupportedEncodingException on errors when encoding.
     * @throws ClaimMetadataException       on errors when getting claim query param.
     */
    private String getQueryParams(AuthenticationContext context, ClaimMapping[] claimMappings, String tenantDomain)
            throws UnsupportedEncodingException, ClaimMetadataException {

        StringBuilder paramBuilder = new StringBuilder();
//        // Set claims query param based on the application's requested attributes.
//        paramBuilder.append(getRequestedClaims(claimMappings, tenantDomain));

//        String discoveryInput = (String) context.getProperty(ORG_DISCOVERY_PARAMETER);
//        if (StringUtils.isNotBlank(discoveryInput)) {
//            paramBuilder.append(AMPERSAND_SIGN).append(LOGIN_HINT_PARAMETER).append(EQUAL_SIGN).append(discoveryInput);
//        }
//
//        if (Boolean.parseBoolean((String) context.getProperty(FrameworkConstants.IS_API_BASED))) {
//            paramBuilder.append(AMPERSAND_SIGN).append(Constants.RESPONSE_MODE).append(EQUAL_SIGN)
//                    .append(Constants.DIRECT);
//        }
//
//        if (context.getProperty(SELF_REGISTRATION_PARAMETER) != null) {
//            paramBuilder.append(AMPERSAND_SIGN).append(SELF_REGISTRATION_PARAMETER).append(EQUAL_SIGN)
//                    .append(context.getProperty(SELF_REGISTRATION_PARAMETER));
//
//            // Used to auto complete the username in self-registration page.
//            if (context.getProperty(ORG_DISCOVERY_PARAMETER) != null &&
//                    EMAIL_DOMAIN_DISCOVERY_TYPE.equals(context.getProperty(ORGANIZATION_DISCOVERY_TYPE))) {
//                paramBuilder.append(AMPERSAND_SIGN).append(USERNAME_PARAMETER).append(EQUAL_SIGN)
//                        .append(context.getProperty(ORG_DISCOVERY_PARAMETER));
//            }
//        }

        String additionalQueryParams = resolveAdditionalQueryParams(context);
        if (StringUtils.isNotBlank(additionalQueryParams)) {
            paramBuilder.append(AMPERSAND_SIGN).append(additionalQueryParams);
        }

        String queryParams = context.getQueryParams();
        String redirectUrl = Arrays.stream(queryParams.split("&"))
                .filter(params -> params.startsWith("redirect_uri="))
                .findFirst()
                .orElse(null);
//        String scopeParams = Arrays.stream(queryParams.split("&"))
//                .filter(params -> params.startsWith("scope="))
//                .findFirst()
//                .orElse(null);

        //  This is required for both request and response
        if (StringUtils.isNotBlank(redirectUrl)) {
            paramBuilder.append("redirect_uri").append(EQUAL_SIGN).append("https://localhost:9443/commonauth");
        }
//        if (StringUtils.isNotBlank(scopeParams) && !isRequestFlow) {
//            paramBuilder.append(AMPERSAND_SIGN).append(scopeParams);
//        }

        return paramBuilder.toString();
    }

    private String resolveAdditionalQueryParams(AuthenticationContext context) {

        Map<String, String> runtimeParams =  getRuntimeParams(context);
        String additionalQueryParams = runtimeParams.get(SSO_ADDITIONAL_PARAMS);
        if (StringUtils.isBlank(additionalQueryParams)) {
            return StringUtils.EMPTY;
        }
        additionalQueryParams = handleAuthParams(runtimeParams, additionalQueryParams);
        additionalQueryParams = handleRequestParams(context, additionalQueryParams);
        return additionalQueryParams;
    }

//    private String getRequestedClaims(ClaimMapping[] claimMappings, String tenantDomain) throws ClaimMetadataException {
//
//        if (claimMappings != null && claimMappings.length > 0) {
//            StringBuilder paramBuilder = new StringBuilder("&claims={\"userinfo\":{");
//            for (ClaimMapping claimMapping : claimMappings) {
//                String oidcClaim = StringUtils.EMPTY;
//                List<Claim> claims = getClaimManager().getMappedExternalClaimsForLocalClaim(
//                        claimMapping.getLocalClaim().getClaimUri(), tenantDomain);
//                if (claims != null) {
//                    for (Claim claim : claims) {
//                        if (OIDC_CLAIM_DIALECT_URL.equals(claim.getClaimDialectURI())) {
//                            oidcClaim = String.format("\"%s\":{\"essential\": true},", claim.getClaimURI());
//                            paramBuilder.append(oidcClaim);
//                        }
//                    }
//                }
//            }
//            paramBuilder.deleteCharAt(paramBuilder.length() - 1);
//            paramBuilder.append("}}");
//            return paramBuilder.toString();
//        }
//        return StringUtils.EMPTY;
//    }

    private String handleAuthParams(Map<String, String> runtimeParams, String queryString) {

        Matcher matcher = Pattern.compile(DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX)
                .matcher(queryString);
        while (matcher.find()) {
            String value = StringUtils.EMPTY;
            String paramName = matcher.group(1);
            if (StringUtils.isNotEmpty(runtimeParams.get(paramName))) {
                value = runtimeParams.get(paramName);
            }
            queryString = queryString.replaceAll("\\$authparam\\{" + paramName + "}", Matcher.quoteReplacement(value));
        }
        return queryString;
    }

    private String handleRequestParams(AuthenticationContext context, String queryString) {

        String requestParamsString = context.getQueryParams();
        Map<String, String> requestParams = new HashMap<>();
        if (StringUtils.isNotBlank(requestParamsString)) {
            String[] params = requestParamsString.split(AMPERSAND_SIGN);
            for (String param : params) {
                String[] keyValue = param.split(EQUAL_SIGN);
                if (keyValue.length == 2) {
                    requestParams.put(keyValue[0], keyValue[1]);
                }
            }
        }
        Matcher matcher = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX)
                .matcher(queryString);
        while (matcher.find()) {
            String paramName = matcher.group(1);
            String value = StringUtils.EMPTY;
            if (requestParams.containsKey(paramName)) {
                value = requestParams.get(paramName);
            }
            queryString = queryString.replaceAll("\\$\\{" + paramName + "}", Matcher.quoteReplacement(value));
        }
        return queryString;
    }


    private void addQueryParam(StringBuilder builder, String query, String param) throws UnsupportedEncodingException {

        builder.append(AMPERSAND_SIGN).append(query).append(EQUAL_SIGN).append(urlEncode(param));
    }

    private String urlEncode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, FrameworkUtils.UTF_8);
    }

    /**
     * Retrieves claim mappings from the federated IDP configured in the Service Provider's
     * Local and Outbound Authentication Configuration.
     * <p>
     * When the SP is configured with a federated authenticator, the claim mappings are defined
     * at the IDP level rather than at the SP level. This method:
     * 1. Extracts the IDP name from the SP's authentication configuration
     * 2. Fetches the full IDP configuration using IdentityProviderManager
     * 3. Returns the claim mappings from the complete IDP configuration
     *
     * @param serviceProvider The service provider configured with federated authentication.
     * @param tenantDomain    The tenant domain to fetch the IDP from.
     * @return Array of claim mappings from the federated IDP, or an empty array if none found.
     */
    private ClaimMapping[] getFederatedIdpClaimMappings(ServiceProvider serviceProvider, String tenantDomain) {

        if (serviceProvider == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service provider is null, returning empty claim mappings.");
            }
            return new ClaimMapping[0];
        }

        LocalAndOutboundAuthenticationConfig authConfig = serviceProvider.getLocalAndOutBoundAuthenticationConfig();
        if (authConfig == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("LocalAndOutboundAuthenticationConfig is null, returning empty claim mappings.");
            }
            return new ClaimMapping[0];
        }

        // Get the authentication steps configured for this SP
        org.wso2.carbon.identity.application.common.model.AuthenticationStep[] authSteps =
                authConfig.getAuthenticationSteps();
        if (authSteps == null || authSteps.length == 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No authentication steps found in authentication config, returning empty claim mappings.");
            }
            return new ClaimMapping[0];
        }

        // Get the first authentication step's federated authenticators
        org.wso2.carbon.identity.application.common.model.AuthenticationStep firstStep = authSteps[0];
        IdentityProvider[] stepIdps = firstStep.getFederatedIdentityProviders();
        if (stepIdps == null || stepIdps.length == 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No federated IDPs found in the first authentication step, returning empty claim mappings.");
            }
            return new ClaimMapping[0];
        }

        // Get the IDP name from the basic IDP reference
        IdentityProvider basicIdpRef = stepIdps[0];
        String idpName = basicIdpRef.getIdentityProviderName();

        if (StringUtils.isBlank(idpName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Federated IDP name is blank, returning empty claim mappings.");
            }
            return new ClaimMapping[0];
        }

        // Fetch the complete IDP configuration using IdentityProviderManager
        try {
            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider fullIdp = idpManager.getIdPByName(idpName, tenantDomain);

            if (fullIdp == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not retrieve full IDP configuration for: " + idpName +
                            " in tenant: " + tenantDomain);
                }
                return new ClaimMapping[0];
            }

            if (fullIdp.getClaimConfig() != null) {
                ClaimMapping[] claimMappings = fullIdp.getClaimConfig().getClaimMappings();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Retrieved " + (claimMappings != null ? claimMappings.length : 0) +
                            " claim mappings from federated IDP '" + idpName +
                            "' in tenant: " + tenantDomain);
                }
                return claimMappings != null ? claimMappings : new ClaimMapping[0];
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Federated IDP '" + idpName + "' claim config is null, returning empty claim mappings.");
            }
            return new ClaimMapping[0];

        } catch (IdentityProviderManagementException e) {
            LOG.error("Error while retrieving IDP '" + idpName + "' for tenant: " + tenantDomain, e);
            return new ClaimMapping[0];
        }
    }
}
