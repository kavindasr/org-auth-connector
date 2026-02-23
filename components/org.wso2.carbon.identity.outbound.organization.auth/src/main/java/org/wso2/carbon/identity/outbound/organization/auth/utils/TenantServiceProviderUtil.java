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

package org.wso2.carbon.identity.outbound.organization.auth.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.outbound.organization.auth.internal.OrganizationAuthDataHolder;

/**
 * Utility class to resolve OAuth2 application credentials (client_id / client_secret)
 * for a given tenant's service provider registered in IS.
 */
public class TenantServiceProviderUtil {

    private static final Log log = LogFactory.getLog(TenantServiceProviderUtil.class);
    private static final String OAUTH2_INBOUND_AUTH_TYPE = "oauth2";

    private TenantServiceProviderUtil() {
    }

    /**
     * Resolve the OAuth2 client ID for a given tenant domain by looking up the
     * specified application name in that tenant's application registry.
     *
     * @param tenantDomain The tenant domain (e.g., "abc.com").
     * @param appName      The name of the service provider / application registered in the tenant.
     * @return The OAuth2 client ID (consumer key) of the application.
     * @throws Exception if the SP is not found or has no OAuth2 inbound config.
     */
    public static String resolveClientId(String tenantDomain, String appName) throws Exception {

        ApplicationManagementService appMgtService =
                OrganizationAuthDataHolder.getInstance().getApplicationManagementService();

        if (appMgtService == null) {
            throw new Exception("ApplicationManagementService is not available. " +
                    "Cannot resolve client ID for tenant: " + tenantDomain);
        }

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);

            ServiceProvider sp = appMgtService.getServiceProvider(appName, tenantDomain);
            if (sp == null) {
                throw new Exception("Service provider '" + appName + "' not found in tenant: " + tenantDomain);
            }

            InboundAuthenticationConfig inboundAuthConfig = sp.getInboundAuthenticationConfig();
            if (inboundAuthConfig == null) {
                throw new Exception("No inbound authentication config found for SP '" + appName +
                        "' in tenant: " + tenantDomain);
            }

            InboundAuthenticationRequestConfig[] authRequestConfigs =
                    inboundAuthConfig.getInboundAuthenticationRequestConfigs();
            if (authRequestConfigs == null) {
                throw new Exception("No inbound authentication request configs found for SP '" + appName +
                        "' in tenant: " + tenantDomain);
            }

            for (InboundAuthenticationRequestConfig config : authRequestConfigs) {
                if (OAUTH2_INBOUND_AUTH_TYPE.equals(config.getInboundAuthType())) {
                    String clientId = config.getInboundAuthKey();
                    if (log.isDebugEnabled()) {
                        log.debug("Resolved client ID for tenant '" + tenantDomain +
                                "', app '" + appName + "': " + clientId);
                    }
                    return clientId;
                }
            }

            throw new Exception("No OAuth2/OIDC inbound authentication config found for SP '" + appName +
                    "' in tenant: " + tenantDomain);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
