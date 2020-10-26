/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.asgardio.java.oidc.sdk;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This class holds the constants used in the module, io.asgardio.java.oidc.sdk.
 */
public class SSOAgentConstants {

    public static final String CONFIG_BEAN_NAME = "io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig";

    // Oauth response parameters and session attributes.
    public static final String ERROR = "error";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID_TOKEN = "id_token";
    public static final String SESSION_STATE = "session_state";
    public static final String USER = "user";
    public static final String REQUEST_CONTEXT = "request_context";
    public static final String SESSION_CONTEXT = "session_context";

    // Keystore file properties.
    public static final String KEYSTORE_NAME = "keystorename";
    public static final String KEYSTORE_PASSWORD = "keystorepassword";

    // Application specific request parameters and session attributes.
    public static final String CONSUMER_KEY = "consumerKey";
    public static final String CONSUMER_SECRET = "consumerSecret";
    public static final String CALL_BACK_URL = "callBackURL";
    public static final String SKIP_URIS = "skipURIs";
    public static final String INDEX_PAGE = "indexPage";
    public static final String LOGOUT_URL = "logoutURL";
    public static final String SCOPE = "scope";
    public static final String OAUTH2_GRANT_TYPE = "grantType";
    public static final String OAUTH2_AUTHZ_ENDPOINT = "authorizeEndpoint";
    public static final String OIDC_LOGOUT_ENDPOINT = "logoutEndpoint";
    public static final String OIDC_SESSION_IFRAME_ENDPOINT = "sessionIFrameEndpoint";
    public static final String OIDC_TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String OIDC_ISSUER = "issuer";
    public static final String OIDC_JWKS_ENDPOINT = "jwksEndpoint";
    public static final String POST_LOGOUT_REDIRECTION_URI = "postLogoutRedirectURI";
    public static final String AUTHENTICATED = "authenticated";
    public static final String OIDC_OPENID = "openid";
    public static final String AZP = "azp";
    public static final String TRUSTED_AUDIENCE = "trustedAudience";
    public static final String ID_TOKEN_SIGN_ALG = "signatureAlgorithm";
    public static final String NONCE = "nonce";

    // Request headers.
    public static final String REFERER = "referer";

    // Context params.
    public static final String APP_PROPERTY_FILE_PARAMETER_NAME = "app-property-file";
    public static final String JKS_PROPERTY_FILE_PARAMETER_NAME = "jks-property-file";

    // Response types.
    public static final String CODE = "code";
    public static final String TOKEN = "token";

    public static final Set<String> OIDC_METADATA_CLAIMS = new HashSet<>(
            Arrays.asList("at_hash", "sub", "iss", "aud", "nbf", "c_hash", "azp", "amr", "sid", "exp", "iat"));

    public enum ErrorMessages {

        AUTHENTICATION_FAILED("18001", "Authentication Failed."),
        ID_TOKEN_NULL("18002", "Null ID token."),
        ID_TOKEN_PARSE("18003", "Error found with parsing the ID token."),
        JWT_PARSE("18004", "Error found with parsing JWT."),
        AGENT_CONFIG_SCOPE("18005",
                "Scope parameter defined incorrectly. Scope parameter must contain the value 'openid'"),
        AGENT_CONFIG_CLIENT_ID("18006",
                "Consumer Key/Client ID must not be null. This refers to the client identifier assigned to the " +
                        "Relying Party during its registration with the OpenID Provider."),
        AGENT_CONFIG_CALLBACK_URL("18007",
                "Callback URL/Redirection URL must not be null. This refers to the Relying Party's redirection URIs " +
                        "registered with the OpenID Provider."),
        SERVLET_CONNECTION("18008", "Error found with connection.");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
