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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import io.asgardio.java.oidc.sdk.bean.AuthenticationContext;
import io.asgardio.java.oidc.sdk.bean.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.bean.User;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class OIDCManagerImpl implements OIDCManager {

    private static final Logger logger = LogManager.getLogger(OIDCManagerImpl.class);

    private OIDCAgentConfig oidcAgentConfig;

    public OIDCManagerImpl(OIDCAgentConfig oidcAgentConfig) {

        this.oidcAgentConfig = oidcAgentConfig;
        //validate config
        //authz code val, logout val
    }

    @Override
    public void init() {

    }

    @Override
    public void sendForLogin(HttpServletRequest request, HttpServletResponse response, String sessionState)
            throws IOException {

        String authorizationRequest = OIDCRequestBuilder.buildAuthorizationRequest(sessionState, oidcAgentConfig);
        response.sendRedirect(authorizationRequest);
    }

    @Override
    public AuthenticationContext authenticate() {

        return null;
    }

    @Override
    public Map<String, Object> getUserInfo() {

        return null;
    }

    @Override
    public void validateAuthentication() {

    }

    @Override
    public AccessToken getAccessToken() {

        return null;
    }

    @Override
    public JWT getIDToken() {

        return null;
    }

    @Override
    public RefreshToken getRefreshToken() {

        return null;
    }

    @Override
    public AuthenticationContext handleOIDCCallback(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        OIDCRequestResolver requestResolver = new OIDCRequestResolver(request, oidcAgentConfig);
        AuthenticationContext context = new AuthenticationContext();

        if (!requestResolver.isError() && requestResolver.isAuthorizationCodeResponse()) {
            logger.log(Level.INFO, "Handling the OIDC Authorization response.");
            try {
                boolean isAuthenticated = handleAuthentication(request, context);
                if (isAuthenticated) {
                    logger.log(Level.INFO, "Authentication successful. Redirecting to the target page.");
                    response.sendRedirect("home.jsp"); //TODO: target page
                } else {
                    logger.log(Level.ERROR, "Authentication failed. Invalidating the session.");
                    request.getSession().invalidate();
                    // redirect to index TODO error.jsp
                    response.sendRedirect(requestResolver.getIndexPage());
                }
            } catch (IOException | SSOAgentServerException e) {
                response.sendRedirect(requestResolver.getIndexPage());
            }
        } else {
            logger.log(Level.INFO, "Clearing the active session and redirecting.");
            clearSession(request);
            response.sendRedirect(requestResolver.getIndexPage());
        }
        return context;
    }

    @Override
    public void logout(AuthenticationContext context, HttpServletResponse response, String sessionState)
            throws IOException {

        LogoutRequest logoutRequest = getLogoutRequest(context, sessionState);
        response.sendRedirect(logoutRequest.toURI().toString());
    }

    @Override
    public boolean isActiveSessionPresent(HttpServletRequest request) {

        HttpSession currentSession = request.getSession(false);

        return currentSession != null
                && currentSession.getAttribute(SSOAgentConstants.AUTHENTICATED) != null
                && (boolean) currentSession.getAttribute(SSOAgentConstants.AUTHENTICATED);
    }

    private LogoutRequest getLogoutRequest(AuthenticationContext context, String sessionState) {

        URI logoutEP = oidcAgentConfig.getLogoutEndpoint();
        URI redirectionURI = oidcAgentConfig.getPostLogoutRedirectURI();
        JWT jwtIdToken = context.getIdToken();
        State state = null;
        if (StringUtils.isNotBlank(sessionState)) {
            state = new State(sessionState);
        }
        return new LogoutRequest(logoutEP, jwtIdToken, redirectionURI, state);
    }

    private void clearSession(HttpServletRequest request) {

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    private boolean handleAuthentication(final HttpServletRequest request, AuthenticationContext context)
            throws SSOAgentServerException, IOException {

        HttpSession session = request.getSession();
        session.invalidate();
        session = request.getSession();

        AuthorizationResponse authorizationResponse;
        AuthorizationCode authorizationCode;
        AuthorizationSuccessResponse successResponse;
        TokenRequest tokenRequest;
        TokenResponse tokenResponse;

        try {
            authorizationResponse = AuthorizationResponse.parse(ServletUtils.createHTTPRequest(request));

            if (!authorizationResponse.indicatesSuccess()) {
                handleErrorAuthorizationResponse(authorizationResponse);
                return false;
            } else {
                successResponse = authorizationResponse.toSuccessResponse();
                authorizationCode = successResponse.getAuthorizationCode();
            }
            tokenRequest = getTokenRequest(authorizationCode);
            tokenResponse = getTokenResponse(tokenRequest);

            if (!tokenResponse.indicatesSuccess()) {
                handleErrorTokenResponse(tokenRequest, tokenResponse);
                return false;
            } else {
                handleSuccessTokenResponse(session, tokenResponse, context);
                return true;
            }
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            logger.error(e.getMessage(), e);
            return false;
        }
    }

    private void handleSuccessTokenResponse(HttpSession session, TokenResponse tokenResponse,
                                            AuthenticationContext context)
            throws SSOAgentServerException {

        AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
        AccessToken accessToken = successResponse.getTokens().getAccessToken();

        session.setAttribute(SSOAgentConstants.ACCESS_TOKEN, accessToken);
        String idToken;
        try {
            idToken = successResponse.getCustomParameters().get(SSOAgentConstants.ID_TOKEN).toString();
        } catch (NullPointerException e) {
            logger.log(Level.ERROR, "id_token is null.");
            throw new SSOAgentServerException("null id token.");
        }

        //TODO validate IdToken (Signature, ref. spec)

//        Issuer issuer = oidcAgentConfig.getIssuer();
//        URL jwkSetURL = oidcAgentConfig.getJwksEndpoint().toURL();
//        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
//        ClientID clientID = oidcAgentConfig.getConsumerKey();
//
//        IDTokenValidator validator = new IDTokenValidator(issuer, clientID, jwsAlgorithm, jwkSetURL);

        try {
//            JWT idTokenJWT = JWTParser.parse(idToken);
//            IDTokenClaimsSet claims;
//
//            Nonce expectedNonce = new Nonce(null);
//            claims = validator.validate(idTokenJWT, expectedNonce);

            JWTClaimsSet claimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();
            User user = new User(claimsSet.getSubject(), getUserAttributes(idToken));
            session.setAttribute(SSOAgentConstants.ID_TOKEN, idToken);
            session.setAttribute(SSOAgentConstants.USER, user);
            session.setAttribute(SSOAgentConstants.AUTHENTICATED, true);

            context.setIdToken(JWTParser.parse(idToken));
            context.setUser(user);
        } catch (ParseException e) {
            throw new SSOAgentServerException("Error while parsing id_token.");
        }
    }

    private void handleErrorTokenResponse(TokenRequest tokenRequest, TokenResponse tokenResponse) {

        TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
        JSONObject requestObject = requestToJson(tokenRequest);
        JSONObject responseObject = errorResponse.toJSONObject();
        logger.log(Level.INFO, "Request object for the error response: ", requestObject);
        logger.log(Level.INFO, "Error response object: ", responseObject);
    }

    private void handleErrorAuthorizationResponse(AuthorizationResponse authzResponse) {

        AuthorizationErrorResponse errorResponse = authzResponse.toErrorResponse();
        JSONObject responseObject = errorResponse.getErrorObject().toJSONObject();
        logger.log(Level.INFO, "Error response object: ", responseObject);
    }

    private TokenResponse getTokenResponse(TokenRequest tokenRequest) {

        TokenResponse tokenResponse = null;
        try {
            tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (com.nimbusds.oauth2.sdk.ParseException | IOException e) {
            logger.log(Level.ERROR, "Error while parsing token response.", e);
        }
        return tokenResponse;
    }

    private TokenRequest getTokenRequest(AuthorizationCode authorizationCode) {

        URI callbackURI = oidcAgentConfig.getCallbackUrl();
        AuthorizationGrant authorizationGrant = new AuthorizationCodeGrant(authorizationCode, callbackURI);
        ClientID clientID = oidcAgentConfig.getConsumerKey();
        Secret clientSecret = oidcAgentConfig.getConsumerSecret();
        ClientAuthentication clientAuthentication = new ClientSecretBasic(clientID, clientSecret);
        URI tokenEndpoint = oidcAgentConfig.getTokenEndpoint();

        return new TokenRequest(tokenEndpoint, clientAuthentication, authorizationGrant);
    }

    private JSONObject requestToJson(AbstractRequest request) {

        JSONObject obj = new JSONObject();
        obj.appendField("tokenEndpoint", request.toHTTPRequest().getURI().toString());
        obj.appendField("request body", request.toHTTPRequest().getQueryParameters());
        return obj;
    }

    private Map<String, Object> getUserAttributes(String idToken) throws SSOAgentServerException {

        Map<String, Object> userClaimValueMap = new HashMap<>();
        try {
            JWTClaimsSet claimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();
            Map<String, Object> customClaimValueMap = claimsSet.getClaims();

            for (String claim : customClaimValueMap.keySet()) {
                if (!SSOAgentConstants.OIDC_METADATA_CLAIMS.contains(claim)) {
                    userClaimValueMap.put(claim, customClaimValueMap.get(claim));
                }
            }
        } catch (ParseException e) {
            throw new SSOAgentServerException("Error while parsing JWT.");
        }
        return userClaimValueMap;
    }
}
