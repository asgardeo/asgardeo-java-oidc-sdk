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
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.asgardio.java.oidc.sdk.bean.AuthenticationInfo;
import io.asgardio.java.oidc.sdk.bean.User;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import io.asgardio.java.oidc.sdk.request.OIDCRequestBuilder;
import io.asgardio.java.oidc.sdk.request.OIDCRequestResolver;
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

public class OIDCManagerImpl implements OIDCManager {

    private static final Logger logger = LogManager.getLogger(OIDCManagerImpl.class);

    private OIDCAgentConfig oidcAgentConfig;

    public OIDCManagerImpl(OIDCAgentConfig oidcAgentConfig) throws SSOAgentClientException {

        validateConfig(oidcAgentConfig);
        this.oidcAgentConfig = oidcAgentConfig;
    }

    @Override
    public void init() {

    }

    @Override
    public void sendForLogin(HttpServletRequest request, HttpServletResponse response, String sessionState)
            throws SSOAgentException {

        OIDCRequestBuilder requestBuilder = new OIDCRequestBuilder(oidcAgentConfig);
        String authorizationRequest = requestBuilder.buildAuthorizationRequest(sessionState);
        try {
            response.sendRedirect(authorizationRequest);
        } catch (IOException e) {
            throw new SSOAgentException(e.getMessage(), e);
        }
    }

    @Override
    public AuthenticationInfo handleOIDCCallback(HttpServletRequest request, HttpServletResponse response)
            throws SSOAgentServerException {

        OIDCRequestResolver requestResolver = new OIDCRequestResolver(request, oidcAgentConfig);
        AuthenticationInfo authenticationInfo = new AuthenticationInfo();

        if (!requestResolver.isError() && requestResolver.isAuthorizationCodeResponse()) {
            logger.log(Level.INFO, "Handling the OIDC Authorization response.");
            boolean isAuthenticated = handleAuthentication(request, authenticationInfo);
            if (isAuthenticated) {
                logger.log(Level.INFO, "Authentication successful. Redirecting to the target page.");
                return authenticationInfo;
            } else {
                logger.log(Level.ERROR, "Authentication failed. Invalidating the session.");
                throw new SSOAgentServerException(SSOAgentConstants.ErrorMessages.AUTHENTICATION_FAILED.getMessage(),
                        SSOAgentConstants.ErrorMessages.AUTHENTICATION_FAILED.getCode());
            }

        } else {
            logger.log(Level.INFO, "Clearing the active session and redirecting.");
            throw new SSOAgentServerException(SSOAgentConstants.ErrorMessages.AUTHENTICATION_FAILED.getMessage(),
                    SSOAgentConstants.ErrorMessages.AUTHENTICATION_FAILED.getCode());
        }
    }

    @Override
    public void logout(AuthenticationInfo context, HttpServletResponse response, String state)
            throws SSOAgentException {

        if (oidcAgentConfig.getPostLogoutRedirectURI() == null) {
            logger.info("postLogoutRedirectURI is not configured. Using the callbackURL instead.");
            URI callbackURI = oidcAgentConfig.getCallbackUrl();
            oidcAgentConfig.setPostLogoutRedirectURI(callbackURI);
        }
        OIDCRequestBuilder requestBuilder = new OIDCRequestBuilder(oidcAgentConfig);
        String logoutRequest = requestBuilder.buildLogoutRequest(context, state);
        try {
            response.sendRedirect(logoutRequest);
        } catch (IOException e) {
            throw new SSOAgentException(SSOAgentConstants.ErrorMessages.SERVLET_CONNECTION.getMessage(),
                    SSOAgentConstants.ErrorMessages.SERVLET_CONNECTION.getCode(), e);
        }
    }

    private boolean handleAuthentication(final HttpServletRequest request, AuthenticationInfo authenticationInfo) {

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
                handleSuccessTokenResponse(tokenResponse, authenticationInfo);
                return true;
            }
        } catch (com.nimbusds.oauth2.sdk.ParseException | SSOAgentServerException | IOException e) {
            logger.error(e.getMessage(), e);
            return false;
        }
    }

    private void handleSuccessTokenResponse(TokenResponse tokenResponse, AuthenticationInfo authenticationInfo)
            throws SSOAgentServerException {

        AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
        AccessToken accessToken = successResponse.getTokens().getAccessToken();
        RefreshToken refreshToken = successResponse.getTokens().getRefreshToken();
        String idToken;
        try {
            idToken = successResponse.getCustomParameters().get(SSOAgentConstants.ID_TOKEN).toString();
        } catch (NullPointerException e) {
            logger.log(Level.ERROR, "id_token is null.");
            throw new SSOAgentServerException(SSOAgentConstants.ErrorMessages.ID_TOKEN_NULL.getMessage(),
                    SSOAgentConstants.ErrorMessages.ID_TOKEN_NULL.getCode(), e);
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

            authenticationInfo.setIdToken(JWTParser.parse(idToken));
            authenticationInfo.setUser(user);
            authenticationInfo.setAccessToken(accessToken);
            authenticationInfo.setRefreshToken(refreshToken);
        } catch (ParseException e) {
            throw new SSOAgentServerException(SSOAgentConstants.ErrorMessages.ID_TOKEN_PARSE.getMessage(),
                    SSOAgentConstants.ErrorMessages.ID_TOKEN_PARSE.getCode(), e);
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
            throw new SSOAgentServerException(SSOAgentConstants.ErrorMessages.JWT_PARSE.getMessage(),
                    SSOAgentConstants.ErrorMessages.JWT_PARSE.getCode(), e);
        }
        return userClaimValueMap;
    }

    private void validateConfig(OIDCAgentConfig oidcAgentConfig) throws SSOAgentClientException {

        validateForCode(oidcAgentConfig);
    }

    private void validateForCode(OIDCAgentConfig oidcAgentConfig) throws SSOAgentClientException {

        Scope scope = oidcAgentConfig.getScope();
        if (scope.isEmpty() || !scope.contains(SSOAgentConstants.OIDC_OPENID)) {
            logger.error("scope defined incorrectly.");
            throw new SSOAgentClientException(SSOAgentConstants.ErrorMessages.AGENT_CONFIG_SCOPE.getMessage(),
                    SSOAgentConstants.ErrorMessages.AGENT_CONFIG_SCOPE.getCode());
        }

        if (oidcAgentConfig.getConsumerKey() == null) {
            logger.error("Consumer Key is null.");
            throw new SSOAgentClientException(SSOAgentConstants.ErrorMessages.AGENT_CONFIG_CLIENT_ID.getMessage(),
                    SSOAgentConstants.ErrorMessages.AGENT_CONFIG_CLIENT_ID.getCode());
        }

        if (StringUtils.isEmpty(oidcAgentConfig.getCallbackUrl().toString())) {
            logger.error("Callback URL is null.");
            throw new SSOAgentClientException(SSOAgentConstants.ErrorMessages.AGENT_CONFIG_CALLBACK_URL.getMessage(),
                    SSOAgentConstants.ErrorMessages.AGENT_CONFIG_CALLBACK_URL.getCode());
        }
    }

    @Override
    public AuthenticationInfo authenticate() {

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
}
