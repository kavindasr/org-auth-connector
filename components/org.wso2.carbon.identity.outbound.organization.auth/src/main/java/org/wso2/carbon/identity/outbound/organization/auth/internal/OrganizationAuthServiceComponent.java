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

package org.wso2.carbon.identity.outbound.organization.auth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.outbound.organization.auth.OrganizationAuthenticator;

import java.util.Hashtable;

@Component(name = "OrganizationAuthServiceComponent", immediate = true)
public class OrganizationAuthServiceComponent {

    private static final Log logger = LogFactory.getLog(OrganizationAuthServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            OrganizationAuthenticator organizationAuthenticator = new OrganizationAuthenticator();
            Hashtable<String, String> props = new Hashtable<>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), organizationAuthenticator,
                    props);
            if (logger.isDebugEnabled()) {
                logger.debug("----Organization Authenticator bundle is activated----");
            }

        } catch (Throwable e) {
            logger.error("----Error while activating Organization authenticator----", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (logger.isDebugEnabled()) {
            logger.debug("----Organization Authenticator bundle is deactivated----");
        }
    }

    @Reference(
            name = "identity.application.management.component",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (logger.isDebugEnabled()) {
            logger.debug("Setting the ApplicationManagementService.");
        }
        OrganizationAuthDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (logger.isDebugEnabled()) {
            logger.debug("Unsetting the ApplicationManagementService.");
        }
        OrganizationAuthDataHolder.getInstance().setApplicationManagementService(null);
    }
}

