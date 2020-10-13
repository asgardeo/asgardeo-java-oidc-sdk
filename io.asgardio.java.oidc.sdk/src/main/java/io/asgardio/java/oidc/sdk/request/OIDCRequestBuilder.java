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

package io.asgardio.java.oidc.sdk.request;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import io.asgardio.java.oidc.sdk.OIDCManager;
import io.asgardio.java.oidc.sdk.bean.AuthenticationInfo;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;

/**
 * OIDCRequestBuilder is the class responsible for building requests
 * for the {@link OIDCManager} based on the {@link OIDCAgentConfig}.
 * <p>
 * OIDCRequestBuilder can build:
 * <ul>
 * <li>Authorization requests
 * <li>Logout requests
 * </ul>
 * <p>
 * and return the String values of the generated requests.
 *
 * @version 0.1.1
 * @since 0.1.1
 */
public class OIDCRequestBuilder {

    private static final Logger logger = LogManager.getLogger(OIDCRequestResolver.class);

    OIDCAgentConfig oidcAgentConfig;

    public OIDCRequestBuilder(OIDCAgentConfig oidcAgentConfig) {

        this.oidcAgentConfig = oidcAgentConfig;
    }

    /**
     * Returns {@link String} Authorization request. To build the authorization request,
     * {@link OIDCAgentConfig} should contain:
     * <ul>
     * <li>The scope
     * <li>The callback URI
     * <li>The authorization endpoint URI
     * </ul>
     *
     * @param state State parameter.
     * @return Authorization request.
     */
    public String buildAuthenticationRequest(String state, Nonce nonce) {

        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        ClientID clientID = oidcAgentConfig.getConsumerKey();
        Scope authScope = oidcAgentConfig.getScope();
        URI callBackURI = oidcAgentConfig.getCallbackUrl();
        URI authorizationEndpoint = oidcAgentConfig.getAuthorizeEndpoint();
        State stateParameter = null;
        if (StringUtils.isNotBlank(state)) {
            stateParameter = new State(state);
        }

        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(responseType, authScope,
                clientID, callBackURI)
                .state(stateParameter)
                .endpointURI(authorizationEndpoint)
                .nonce(nonce)
                .build();

        return authenticationRequest.toURI().toString();


//        AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(responseType, clientID)
//                .scope(authScope)
//                .state(stateParameter)
//                .redirectionURI(callBackURI)
//                .endpointURI(authorizationEndpoint)
//                .build();
//        return authorizationRequest.toURI().toString();
    }

    /**
     * Returns {@link String} Logout request. To build the logout request,
     * {@link OIDCAgentConfig} should contain:
     * <ul>
     * <li>The logout endpoint URI
     * <li>The post logout redirection URI
     * </ul>
     *
     * @param authenticationInfo {@link AuthenticationInfo} object with information of the current LoggedIn session.
     *                           It must include a valid ID token.
     * @param state              State parameter.
     * @return Logout request.
     */
    public String buildLogoutRequest(AuthenticationInfo authenticationInfo, String state) {

        URI logoutEP = oidcAgentConfig.getLogoutEndpoint();
        URI redirectionURI = oidcAgentConfig.getPostLogoutRedirectURI();
        JWT jwtIdToken = authenticationInfo.getIdToken();
        State stateParam = null;
        if (StringUtils.isNotBlank(state)) {
            stateParam = new State(state);
        }
        return new LogoutRequest(logoutEP, jwtIdToken, redirectionURI, stateParam).toURI().toString();
    }
}
