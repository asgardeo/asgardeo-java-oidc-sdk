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

package io.asgardio.java.oidc.sdk.config.model;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.testng.annotations.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.assertEquals;

public class OIDCAgentConfigTest {

    OIDCAgentConfig oidcAgentConfig = new OIDCAgentConfig();

    @Test
    public void testGetConsumerKey() {

        ClientID clientID = new ClientID("sampleClientId");
        oidcAgentConfig.setConsumerKey(clientID);
        assertEquals(oidcAgentConfig.getConsumerKey(), clientID);
    }

    @Test
    public void testGetConsumerSecret() {

        Secret clientSecret = new Secret("sampleClientSecret");
        oidcAgentConfig.setConsumerSecret(clientSecret);
        assertEquals(oidcAgentConfig.getConsumerSecret(), clientSecret);
    }

    @Test
    public void testGetIndexPage() {

        String indexPage = "/sample/indexPage";
        oidcAgentConfig.setIndexPage(indexPage);
        assertEquals(oidcAgentConfig.getIndexPage(), indexPage);
    }

    @Test
    public void testGetLogoutURL() {

        String logoutURL = "/sample/logout";
        oidcAgentConfig.setLogoutURL(logoutURL);
        assertEquals(oidcAgentConfig.getLogoutURL(), logoutURL);
    }

    @Test
    public void testGetCallbackUrl() throws URISyntaxException {

        URI callbackURL = new URI("http://test/sampleCallback");
        oidcAgentConfig.setCallbackUrl(callbackURL);
        assertEquals(oidcAgentConfig.getCallbackUrl(), callbackURL);
    }

    @Test
    public void testGetScope() {

        Scope scope = new Scope("sampleScope1", "sampleScope2");
        oidcAgentConfig.setScope(scope);
        assertEquals(oidcAgentConfig.getScope(), scope);
    }

    @Test
    public void testGetAuthorizeEndpoint() throws URISyntaxException {

        URI authorizeURL = new URI("http://test/sampleAuthzEP");
        oidcAgentConfig.setAuthorizeEndpoint(authorizeURL);
        assertEquals(oidcAgentConfig.getAuthorizeEndpoint(), authorizeURL);
    }

    @Test
    public void testGetLogoutEndpoint() throws URISyntaxException {

        URI logoutEPURI = new URI("http://test/sampleLogoutEP");
        oidcAgentConfig.setLogoutEndpoint(logoutEPURI);
        assertEquals(oidcAgentConfig.getLogoutEndpoint(), logoutEPURI);
    }

    @Test
    public void testGetTokenEndpoint() throws URISyntaxException {

        URI tokenEPURI = new URI("http://test/sampleTokenEP");
        oidcAgentConfig.setTokenEndpoint(tokenEPURI);
        assertEquals(oidcAgentConfig.getTokenEndpoint(), tokenEPURI);
    }

    @Test
    public void testGetIssuer() {

        Issuer issuer = new Issuer("issuer");
        oidcAgentConfig.setIssuer(issuer);
        assertEquals(oidcAgentConfig.getIssuer(), issuer);
    }

    @Test
    public void testGetJwksEndpoint() throws URISyntaxException {

        URI jwksEPURI = new URI("http://test/sampleJwksEP");
        oidcAgentConfig.setJwksEndpoint(jwksEPURI);
        assertEquals(oidcAgentConfig.getJwksEndpoint(), jwksEPURI);
    }

    @Test
    public void testGetPostLogoutRedirectURI() throws URISyntaxException {

        URI redirectURI = new URI("http://test/sampleLogoutRedirect");
        oidcAgentConfig.setPostLogoutRedirectURI(redirectURI);
        assertEquals(oidcAgentConfig.getPostLogoutRedirectURI(), redirectURI);
    }

    @Test
    public void testGetSkipURIs() {

        Set<String> skipURIs = new HashSet<String>();
        skipURIs.add("sampleSkipURI1");
        skipURIs.add("sampleSkipURI2");
        oidcAgentConfig.setSkipURIs(skipURIs);
        assertEquals(oidcAgentConfig.getSkipURIs(), skipURIs);
    }
}
