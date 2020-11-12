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
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import io.asgardio.java.oidc.sdk.OIDCManager;
import io.asgardio.java.oidc.sdk.bean.RequestContext;
import io.asgardio.java.oidc.sdk.bean.SessionContext;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.text.ParseException;
import java.util.UUID;

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
 */
public class OIDCRequestBuilder {

    private static final Logger logger = LogManager.getLogger(OIDCRequestResolver.class);

    OIDCAgentConfig oidcAgentConfig;

    public OIDCRequestBuilder(OIDCAgentConfig oidcAgentConfig) {

        this.oidcAgentConfig = oidcAgentConfig;
    }

    /**
     * Returns {@link io.asgardio.java.oidc.sdk.request.model.AuthenticationRequest} Authentication request.
     * To build the authentication request, {@link OIDCAgentConfig} should contain:
     * <ul>
     * <li>The client ID
     * <li>The scope
     * <li>The callback URI
     * <li>The authorization endpoint URI
     * </ul>
     *
     * @return Authentication request.
     */
    public io.asgardio.java.oidc.sdk.request.model.AuthenticationRequest buildAuthenticationRequest() {

        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        ClientID clientID = oidcAgentConfig.getConsumerKey();
        Scope authScope = oidcAgentConfig.getScope();
        URI callBackURI = oidcAgentConfig.getCallbackUrl();
        URI authorizationEndpoint = oidcAgentConfig.getAuthorizeEndpoint();
        State state = generateStateParameter();
        Nonce nonce = new Nonce();
        RequestContext requestContext = new RequestContext(state, nonce);

        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(responseType, authScope,
                clientID, callBackURI)
                .state(state)
                .endpointURI(authorizationEndpoint)
                .nonce(nonce)
                .build();

        io.asgardio.java.oidc.sdk.request.model.AuthenticationRequest authRequest =
                new io.asgardio.java.oidc.sdk.request.model.AuthenticationRequest(authenticationRequest.toURI(),
                        requestContext);

        return authRequest;
    }

    /**
     * Returns {@link io.asgardio.java.oidc.sdk.request.model.LogoutRequest} Logout request. To build the logout request,
     * {@link OIDCAgentConfig} should contain:
     * <ul>
     * <li>The logout endpoint URI
     * <li>The post logout redirection URI
     * </ul>
     *
     * @param sessionContext {@link SessionContext} object with information of the current LoggedIn session.
     *                       It must include a valid ID token.
     * @return Logout request.
     */
    public io.asgardio.java.oidc.sdk.request.model.LogoutRequest buildLogoutRequest(SessionContext sessionContext)
            throws SSOAgentServerException {

        URI logoutEP = oidcAgentConfig.getLogoutEndpoint();
        URI redirectionURI = oidcAgentConfig.getPostLogoutRedirectURI();
        JWT jwtIdToken = null;
        try {
            jwtIdToken = JWTParser.parse(sessionContext.getIdToken());
        } catch (ParseException e) {
            throw new SSOAgentServerException(e.getMessage(), e);
        }
        State state = generateStateParameter();
        RequestContext requestContext = new RequestContext();

        requestContext.setState(state);
        URI logoutRequestURI;

        try {
            logoutRequestURI = new LogoutRequest(logoutEP, jwtIdToken, redirectionURI, state).toURI();
        } catch (Exception e) {
            throw new SSOAgentServerException(e.getMessage(), e);
        }

        return new io.asgardio.java.oidc.sdk.request.model.LogoutRequest(logoutRequestURI, requestContext);
    }

    private State generateStateParameter() {

        UUID uuid = UUID.randomUUID();
        return new State(uuid.toString());
    }
}
