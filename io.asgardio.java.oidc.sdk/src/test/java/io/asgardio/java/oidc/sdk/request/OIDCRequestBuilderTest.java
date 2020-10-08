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
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import io.asgardio.java.oidc.sdk.bean.AuthenticationInfo;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({OIDCAgentConfig.class})
public class OIDCRequestBuilderTest extends PowerMockTestCase {

    @Mock
    OIDCAgentConfig oidcAgentConfig;

    @Mock
    AuthenticationInfo authenticationInfo;

    @BeforeMethod
    public void setUp() throws URISyntaxException, ParseException {

        ClientID clientID = new ClientID("sampleClientId");
        Scope scope = new Scope("sampleScope1", "sampleScope2");
        URI callbackURI = new URI("http://test/sampleCallbackURL");
        URI authorizationEndpoint = new URI("http://test/sampleAuthzEP");
        URI logoutEP = new URI("http://test/sampleLogoutEP");
        URI redirectionURI = new URI("http://test/sampleRedirectionURL");
        JWT idToken = JWTParser
                .parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwia" +
                        "WF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

        oidcAgentConfig = mock(OIDCAgentConfig.class);
        authenticationInfo = mock(AuthenticationInfo.class);

        when(oidcAgentConfig.getConsumerKey()).thenReturn(clientID);
        when(oidcAgentConfig.getScope()).thenReturn(scope);
        when(oidcAgentConfig.getCallbackUrl()).thenReturn(callbackURI);
        when(oidcAgentConfig.getAuthorizeEndpoint()).thenReturn(authorizationEndpoint);
        when(oidcAgentConfig.getLogoutEndpoint()).thenReturn(logoutEP);
        when(oidcAgentConfig.getPostLogoutRedirectURI()).thenReturn(redirectionURI);

        when(authenticationInfo.getIdToken()).thenReturn(idToken);
    }

    @Test
    public void testBuildAuthorizationRequest() {

        String authorizationRequest = new OIDCRequestBuilder(oidcAgentConfig).buildAuthorizationRequest("state");
        assertEquals(authorizationRequest, "http://test/sampleAuthzEP?response_type=code&redirect_uri=http%3A%2F" +
                "%2Ftest%2FsampleCallbackURL&state=state&client_id=sampleClientId&scope=sampleScope1+sampleScope2");
    }

    @Test
    public void testBuildLogoutRequest() {

        String logoutRequest = new OIDCRequestBuilder(oidcAgentConfig).buildLogoutRequest(authenticationInfo,
                "state");
        assertEquals(logoutRequest, "http://test/sampleLogoutEP?state=state&post_logout_redirect_uri=http%3A%2F%2" +
                "Ftest%2FsampleRedirectionURL&id_token_hint=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3O" +
                "DkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }
}