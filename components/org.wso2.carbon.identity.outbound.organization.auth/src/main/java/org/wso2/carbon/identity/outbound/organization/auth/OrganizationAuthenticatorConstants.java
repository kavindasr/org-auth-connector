/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

public class OrganizationAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "orgAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Organization Authenticator";
    public static final String REDIRECT_URL = "redirectUrl";
    public static final String KAKAO_AUTH_URL = "https://kauth.kakao.com/oauth/authorize";
    public static final String KAKAO_TOKEN_URL = "https://kauth.kakao.com/oauth/token";
    public static final String KAKAO_INFO_URL = "https://kapi.kakao.com/v2/user/me";
    public static final String KAKAO_OAUTH2_STATE_SUFFIX = ",oauth2";

    private OrganizationAuthenticatorConstants() {
    }

    /**
     * Enum for error messages.
     */
    public enum ErrorMessages {

        NO_REGISTERED_IDP_FOR_ISSUER("Kakao-65001", "No registered IdP found for the issuer: %s"),
        JWT_TOKEN_VALIDATION_FAILED("Kakao-65002", "Error while validating the ID token."),
        ID_TOKEN_AUD_VALIDATION_FAILED("Kakao-65003", "Invalid audience in the ID token.");

        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s  - %s", code, message);
        }
    }
}

