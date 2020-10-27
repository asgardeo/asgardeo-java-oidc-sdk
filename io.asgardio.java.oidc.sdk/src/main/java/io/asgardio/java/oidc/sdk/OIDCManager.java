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

import io.asgardio.java.oidc.sdk.bean.AuthenticationRequest;
import io.asgardio.java.oidc.sdk.bean.RequestContext;
import io.asgardio.java.oidc.sdk.bean.SessionContext;
import io.asgardio.java.oidc.sdk.bean.User;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC manager service interface.
 */
public interface OIDCManager {

    /**
     * Builds an authentication request and redirects.
     *
     * @param request  Incoming {@link HttpServletRequest}.
     * @param response Outgoing {@link HttpServletResponse}
     * @return {@link RequestContext} Object containing details regarding the state ID, nonce value for the
     * {@link AuthenticationRequest}.
     * @throws SSOAgentException
     */
    RequestContext sendForLogin(HttpServletRequest request, HttpServletResponse response)
            throws SSOAgentException;

    /**
     * Processes the OIDC callback response and extract the authorization code, builds a token request, sends the
     * token request and parse the token response where the authenticated user info and tokens would be added to the
     * {@link SessionContext} object and returned.
     *
     * @param request        Incoming {@link HttpServletRequest}.
     * @param response       Outgoing {@link HttpServletResponse}.
     * @param requestContext {@link RequestContext} object containing the authentication request related information.
     * @return {@link SessionContext} Object containing the authenticated {@link User}, AccessToken, RefreshToken
     * and IDToken.
     * @throws SSOAgentException Upon failed authentication.
     */
    SessionContext handleOIDCCallback(HttpServletRequest request, HttpServletResponse response,
                                      RequestContext requestContext) throws SSOAgentException;

    /**
     * Builds a logout request and redirects.
     *
     * @param sessionContext {@link SessionContext} of the logged in session.
     * @param response       Outgoing {@link HttpServletResponse}
     * @throws SSOAgentException
     */
    void logout(SessionContext sessionContext, HttpServletResponse response) throws SSOAgentException;
}
