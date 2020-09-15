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

import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import io.asgardio.java.oidc.sdk.bean.OIDCAgentConfig;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

public class OIDCRequestResolver {

    private static final Logger logger = LogManager.getLogger(OIDCRequestResolver.class);

    OIDCAgentConfig oidcAgentConfig = null;
    HttpServletRequest request = null;

    public OIDCRequestResolver(HttpServletRequest request, OIDCAgentConfig oidcAgentConfig) {

        this.request = request;
        this.oidcAgentConfig = oidcAgentConfig;
    }

    public boolean isError() {

        String error = request.getParameter(SSOAgentConstants.ERROR);
        return StringUtils.isNotBlank(error);
    }

    public boolean isAuthorizationCodeResponse() {

        AuthorizationResponse authorizationResponse;
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
        return true;
    }

    public boolean isLogoutURL() {

        return request.getRequestURI().endsWith(oidcAgentConfig.getLogoutURL());
    }

    public boolean isSkipURI() {

        return oidcAgentConfig.getSkipURIs().contains(request.getRequestURI());
    }

    public boolean isCallbackResponse() {

        String callbackContext = oidcAgentConfig.getCallbackUrl().getPath();
        return request.getRequestURI().contains(callbackContext);
    }

    public String getIndexPage() {

        String indexPage = oidcAgentConfig.getIndexPage();
        if (StringUtils.isNotBlank(indexPage)) {
            return indexPage;
        }
        return request.getContextPath();
    }
    private void logErrorAuthorizationResponse(AuthorizationResponse authzResponse) {

        AuthorizationErrorResponse errorResponse = authzResponse.toErrorResponse();
        JSONObject responseObject = errorResponse.getErrorObject().toJSONObject();
        logger.log(Level.INFO, "Error response object: ", responseObject);
    }



}
