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

package io.asgardeo.java.oidc.sdk.request;

import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import io.asgardeo.java.oidc.sdk.SSOAgentConstants;
import io.asgardeo.java.oidc.sdk.config.model.OIDCAgentConfig;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

/**
 * OIDCRequestResolver is the class responsible for resolving requests
 * based on the {@link OIDCAgentConfig} and the request parameters.
 * <p>
 * OIDCRequestResolver verifies if:
 * <ul>
 * <li>The request is a URL to skip
 * <li>The request is a Logout request
 * <li>The request is an error
 * <li>The request contains an authorization code response
 * <li>The request is a callback response
 * </ul>
 * <p>
 * and returns boolean values.
 */
public class OIDCRequestResolver {

    private static final Logger logger = LogManager.getLogger(OIDCRequestResolver.class);

    OIDCAgentConfig oidcAgentConfig;
    HttpServletRequest request;

    public OIDCRequestResolver(HttpServletRequest request, OIDCAgentConfig oidcAgentConfig) {

        this.request = request;
        this.oidcAgentConfig = oidcAgentConfig;
    }

    /**
     * Checks if the request contains a parameter, "error".
     *
     * @return True if the request contains an "error" parameter, false otherwise.
     */
    public boolean isError() {

        String error = request.getParameter(SSOAgentConstants.ERROR);
        return StringUtils.isNotBlank(error);
    }

    /**
     * Checks if the request is an Authorization Code response.
     *
     * @return True if the request is parsed as a valid Authorization response, false otherwise.
     */
    public boolean isAuthorizationCodeResponse() {

        AuthorizationResponse authorizationResponse;
        AuthorizationSuccessResponse authorizationSuccessResponse;

        try {
            authorizationResponse = AuthorizationResponse.parse(ServletUtils.createHTTPRequest(request));
        } catch (com.nimbusds.oauth2.sdk.ParseException | IOException e) {
            logger.log(Level.ERROR, "Error occurred while parsing the authorization response.", e);
            return false;
        }
        if (!authorizationResponse.indicatesSuccess()) {
            logErrorAuthorizationResponse(authorizationResponse);
            return false;
        }
        authorizationSuccessResponse = authorizationResponse.toSuccessResponse();
        if (authorizationSuccessResponse.getAuthorizationCode() == null) {
            return false;
        }
        return true;
    }

    /**
     * Checks if the request is a logout request.
     *
     * @return True if the request ends with the logout URL configured in the {@link OIDCAgentConfig}, false otherwise.
     */
    public boolean isLogoutURL() {

        return request.getRequestURI().endsWith(oidcAgentConfig.getLogoutURL());
    }

    /**
     * Checks if the request is a URI to skip.
     *
     * @return True if the request is a URL configured in the {@link OIDCAgentConfig} as skipURIs, false otherwise.
     */
    public boolean isSkipURI() {

        return oidcAgentConfig.getSkipURIs().contains(request.getRequestURI());
    }

    /**
     * Checks if the request contains is_logout parameter.
     *
     * @return True if the request contains a parameter called is_logout and its value is true, false otherwise.
     */
    public boolean isLogout() {

        if (request.getAttribute(SSOAgentConstants.IS_LOGOUT) != null) {
            return (boolean) request.getAttribute(SSOAgentConstants.IS_LOGOUT);
        }
        return false;
    }

    /**
     * Checks if the request is a callback response.
     *
     * @return True if the request contains the path of the callback URL configured in the {@link OIDCAgentConfig},
     * false otherwise.
     */
    public boolean isCallbackResponse() {

        String callbackContext = oidcAgentConfig.getCallbackUrl().getPath();

        return request.getRequestURI().contains(callbackContext);
    }

    private void logErrorAuthorizationResponse(AuthorizationResponse authzResponse) {

        AuthorizationErrorResponse errorResponse = authzResponse.toErrorResponse();
        JSONObject responseObject = errorResponse.getErrorObject().toJSONObject();

        logger.log(Level.INFO, "Error response object: ", responseObject);
    }
}
