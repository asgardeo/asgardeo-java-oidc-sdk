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

import com.nimbusds.openid.connect.sdk.Nonce;
import io.asgardio.java.oidc.sdk.bean.AuthenticationInfo;
import io.asgardio.java.oidc.sdk.bean.User;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC manager service interface.
 *
 * @version 0.1.1
 * @since 0.1.1
 */
public interface OIDCManager {

    /**
     * Builds an authentication request and redirects.
     *
     * @param request  Incoming {@link HttpServletRequest}.
     * @param response Outgoing {@link HttpServletResponse}
     * @param state    State parameter for the session.
     * @throws SSOAgentException
     */
    void sendForLogin(HttpServletRequest request, HttpServletResponse response, String state)
            throws SSOAgentException;

    /**
     * Processes the OIDC callback response and extract the authorization code, builds a token request, sends the
     * token request and parse the token response where the authenticated user info and tokens would be added to the
     * {@link AuthenticationInfo} object and returned.
     *
     * @param request  Incoming {@link HttpServletRequest}.
     * @param response Outgoing {@link HttpServletResponse}
     * @return {@link AuthenticationInfo} Object containing the authenticated {@link User}, AccessToken, RefreshToken
     * and IDToken.
     * @throws SSOAgentException Upon failed authentication.
     */
    AuthenticationInfo handleOIDCCallback(HttpServletRequest request, HttpServletResponse response)
            throws SSOAgentException;

    /**
     * Builds a logout request and redirects.
     *
     * @param authenticationInfo {@link AuthenticationInfo} of the logged in session.
     * @param response           Outgoing {@link HttpServletResponse}
     * @param state              State parameter for the session.
     * @throws SSOAgentException
     */
    void logout(AuthenticationInfo authenticationInfo, HttpServletResponse response, String state)
            throws SSOAgentException;

//    void init();
//
//    AuthenticationInfo authenticate();
//
//    Map<String, Object> getUserInfo();
//
//    void validateAuthentication();
//
//    AccessToken getAccessToken();
//
//    JWT getIDToken();
//
//    RefreshToken getRefreshToken();

}
