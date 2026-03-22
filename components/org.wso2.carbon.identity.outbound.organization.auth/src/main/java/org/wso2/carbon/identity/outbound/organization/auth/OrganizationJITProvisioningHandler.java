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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.JITProvisioningPostAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.SUPER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticatorConstants.USER_SELECTED_TENANT_DOMAIN;

/**
 * Custom JIT Provisioning Post Authentication Handler for Organization Authenticator.
 * <p>
 * This handler extends the {@link JITProvisioningPostAuthenticationHandler} to conditionally
 * execute JIT provisioning based on the tenant domain selected by the user.
 * <p>
 * JIT provisioning is only performed when:
 * <ul>
 *   <li>The {@code USER_SELECTED_TENANT_DOMAIN} context property is not set, OR</li>
 *   <li>The {@code USER_SELECTED_TENANT_DOMAIN} equals "carbon.super"</li>
 * </ul>
 * <p>
 * For other tenant domains, JIT provisioning is skipped as the user is already authenticated
 * against the target tenant's identity provider.
 */
public class OrganizationJITProvisioningHandler extends JITProvisioningPostAuthenticationHandler {

    private static final Log LOG = LogFactory.getLog(OrganizationJITProvisioningHandler.class);

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest request, HttpServletResponse response,
                                             AuthenticationContext context)
            throws PostAuthenticationFailedException {

        String userSelectedTenantDomain = (String) context.getProperty(USER_SELECTED_TENANT_DOMAIN);

        // Execute JIT provisioning only if:
        // 1. USER_SELECTED_TENANT_DOMAIN property is not set (null or blank), OR
        // 2. USER_SELECTED_TENANT_DOMAIN equals "carbon.super"
        if ((userSelectedTenantDomain == null && shouldProvision(context)) || SUPER_TENANT_DOMAIN.equals(userSelectedTenantDomain)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User selected tenant domain is '" + userSelectedTenantDomain +
                        "'. Proceeding with JIT provisioning.");
            }
            return super.handle(request, response, context);
        }

        // Skip JIT provisioning for non-super tenant domains
        if (LOG.isDebugEnabled()) {
            LOG.debug("Skipping JIT provisioning for tenant domain: " + userSelectedTenantDomain);
        }

        // Return SUCCESS_COMPLETED to indicate this handler has completed successfully
        // without performing any provisioning action
        return PostAuthnHandlerFlowStatus.UNSUCCESS_COMPLETED;
    }

    @Override
    public String getName() {

        return "OrganizationJITProvisioningHandler";
    }

    // This method covered the scenario where the user is JitProvisioned outside the Organization Authenticator flow.
    private boolean shouldProvision(AuthenticationContext context) {

        String tenantDomain = context.getTenantDomain();
        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        for(AuthenticatedIdPData idpData : currentAuthenticatedIdPs.values()) {
            AuthenticatedUser authenticatedUser = idpData.getUser();
            String tenantDomainFromUser = extractTenantDomainFromAuthenticatedUser(authenticatedUser);
            if (tenantDomainFromUser == null) {
                tenantDomainFromUser = authenticatedUser.getTenantDomain();
            }
            if (tenantDomainFromUser != null && tenantDomainFromUser.equals(tenantDomain)) {
                return true;
            }
        }
        return false;

    }

    private String extractTenantDomainFromAuthenticatedUser(AuthenticatedUser user) {

        if (user == null) {
            return null;
        }
        String userName = user.getUserName();
        if (userName != null && userName.contains("@")) {
            return userName.substring(userName.indexOf("@") + 1);
        }
        return null;
    }
}




