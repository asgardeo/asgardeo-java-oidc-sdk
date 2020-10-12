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
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import io.asgardio.java.oidc.sdk.bean.AuthenticationInfo;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;
import io.asgardio.java.oidc.sdk.request.OIDCRequestResolver;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockserver.integration.ClientAndServer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class OIDCManagerImplTest {

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    OIDCRequestResolver requestResolver;

    @Mock
    AuthenticationInfo authenticationInfo;

    OIDCAgentConfig oidcAgentConfig = new OIDCAgentConfig();

    private ClientAndServer mockServer;

    @BeforeMethod
    public void setUp() throws URISyntaxException, java.text.ParseException {

        mockServer = ClientAndServer.startClientAndServer(9443);
        ClientID clientID = new ClientID("sampleClientId");
        Secret clientSecret = new Secret("sampleClientSceret");
        URI callbackURI = new URI("http://localhost:9443/sampleCallbackURL");
        URI tokenEPURI = new URI("http://localhost:9443/sampleTokenEP");
        URI logoutEP = new URI("http://test/sampleLogoutEP");
        Scope scope = new Scope("sampleScope1", "openid");
        JWT idToken = JWTParser
                .parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwia" +
                        "WF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        requestResolver = mock(OIDCRequestResolver.class);
        authenticationInfo = mock(AuthenticationInfo.class);

        oidcAgentConfig.setConsumerKey(clientID);
        oidcAgentConfig.setConsumerSecret(clientSecret);
        oidcAgentConfig.setCallbackUrl(callbackURI);
        oidcAgentConfig.setTokenEndpoint(tokenEPURI);
        oidcAgentConfig.setLogoutEndpoint(logoutEP);
        oidcAgentConfig.setScope(scope);
        when(authenticationInfo.getIdToken()).thenReturn(idToken);
    }

    @Test
    public void testHandleOIDCCallback() throws SSOAgentException, IOException, ParseException {

        AccessToken accessToken = new AccessToken(AccessTokenType.BEARER, "sampleAccessToken") {
            @Override
            public String toAuthorizationHeader() {

                return null;
            }
        };
        RefreshToken refreshToken = new RefreshToken("sampleRefreshToken");
        Tokens tokens = new Tokens(accessToken, refreshToken);
        Map<String, Object> customParameters = new HashMap<>();
        String parsedIdToken = "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdS" +
                "bE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlR" +
                "BM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ" +
                ".eyJhdF9oYXNoIjoiSEJOUlJOeTlaVy1CMXF3dFdLRkJEZyIsInN1YiI6ImFsZXhAY2FyYm9uLnN1cGVyIiwiY291bnRyeSI6Ik" +
                "xLIiwiYW1yIjpbIkJhc2ljQXV0aGVudGljYXRvciJdLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvd" +
                "G9rZW4iLCJzaWQiOiJkYmJhNGNkMC0wNWRjLTQxN2QtYTcwYy1lOGNmYmNiNDlhMDMiLCJhdWQiOiJLRTRPWWVZX2dmWXd6UWJK" +
                "YTl0R2hqMWhaSk1hIiwiY19oYXNoIjoiWXhUQ25rZ2UtOG9PSWZ3RUpmS2tfdyIsIm5iZiI6MTYwMjIyNjA5MSwiYXpwIjoiS0U" +
                "0T1llWV9nZll3elFiSmE5dEdoajFoWkpNYSIsImV4cCI6MTYwMjIyOTY5MSwiaWF0IjoxNjAyMjI2MDkxLCJlbWFpbCI6ImFsZX" +
                "hAd3NvMi5jb20ifQ.pHwsQqn64tif2J6iYcRShK_85WO3aBuL7Pz8urcHErXjyh6zvroOqSWD9KbSxJPocyoIshdqWdAEhdURKL" +
                "tXiw-l73HlvnX4qJKYT71VKXMTC26Z8dlk4TgytXiskmj8OpAcem3czuEWTrTLVbYzIw71p9kx-5Xxb9WNvzBg1YpwGC8MK3dkW" +
                "TfmUsu6oncIvHyv-gbX3kJebgMserp";
        customParameters.put(SSOAgentConstants.ID_TOKEN, parsedIdToken);

        when(requestResolver.isError()).thenReturn(false);
        when(requestResolver.isAuthorizationCodeResponse()).thenReturn(true);

        MockedStatic<AuthorizationResponse> mockedAuthorizationResponse = mockStatic(AuthorizationResponse.class);
        MockedStatic<ServletUtils> mockedServletUtils = mockStatic(ServletUtils.class);
        MockedStatic<TokenResponse> mockedTokenResponse = mockStatic(TokenResponse.class);
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        AuthorizationResponse authorizationResponse = mock(AuthorizationResponse.class);
        AuthorizationSuccessResponse successResponse = mock(AuthorizationSuccessResponse.class);
        AuthorizationCode authorizationCode = mock(AuthorizationCode.class);
        TokenResponse tokenResponse = mock(TokenResponse.class);
        AccessTokenResponse accessTokenResponse = mock(AccessTokenResponse.class);
        when(ServletUtils.createHTTPRequest(request)).thenReturn(httpRequest);
        when(AuthorizationResponse.parse(httpRequest)).thenReturn(authorizationResponse);
        when(authorizationResponse.indicatesSuccess()).thenReturn(true);
        when(authorizationResponse.toSuccessResponse()).thenReturn(successResponse);
        when(successResponse.getAuthorizationCode()).thenReturn(authorizationCode);
        when(TokenResponse.parse((HTTPResponse) any())).thenReturn(tokenResponse);
        when(tokenResponse.indicatesSuccess()).thenReturn(true);
        when(tokenResponse.toSuccessResponse()).thenReturn(accessTokenResponse);
        when(accessTokenResponse.getTokens()).thenReturn(tokens);
        when(accessTokenResponse.getCustomParameters()).thenReturn(customParameters);

        OIDCManager oidcManager = new OIDCManagerImpl(oidcAgentConfig);
        AuthenticationInfo authenticationInfo = oidcManager.handleOIDCCallback(request, response);

        assertEquals(authenticationInfo.getAccessToken(), accessToken);
        assertEquals(authenticationInfo.getRefreshToken(), refreshToken);
        assertEquals(authenticationInfo.getIdToken().getParsedString(), parsedIdToken);
        assertEquals(authenticationInfo.getUser().getSubject(), "alex@carbon.super");

        mockedAuthorizationResponse.close();
        mockedServletUtils.close();
        mockedTokenResponse.close();
    }

    @Test
    public void testLogoutCallbackURI() throws SSOAgentException {

        oidcAgentConfig.setPostLogoutRedirectURI(null);
        OIDCManager oidcManager = new OIDCManagerImpl(oidcAgentConfig);
        oidcManager.logout(authenticationInfo, response, "state");
    }

    @Test
    public void testLogoutRedirectURI() throws URISyntaxException, SSOAgentException {

        URI redirectionURI = new URI("http://test/sampleRedirectionURL");
        oidcAgentConfig.setPostLogoutRedirectURI(redirectionURI);
        OIDCManager oidcManager = new OIDCManagerImpl(oidcAgentConfig);
        oidcManager.logout(authenticationInfo, response, "state");
    }

    @AfterMethod
    public void tearDown() {

        mockServer.stop();
    }
}