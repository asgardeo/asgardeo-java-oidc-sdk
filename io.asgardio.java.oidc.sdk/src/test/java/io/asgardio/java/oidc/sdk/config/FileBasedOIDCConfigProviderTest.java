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

package io.asgardio.java.oidc.sdk.config;

import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class FileBasedOIDCConfigProviderTest {

    InputStream inputStream;

    @BeforeMethod
    public void setUp() {

        File file = new File("src/test/resources/oidc-sample-app.properties");
        try {
            inputStream = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            //Mock behaviour. Hence ignored.
        }

    }

    @Test
    public void testGetOidcAgentConfig() throws SSOAgentClientException {

        FileBasedOIDCConfigProvider configProvider = new FileBasedOIDCConfigProvider(inputStream);
        OIDCAgentConfig oidcAgentConfig = configProvider.getOidcAgentConfig();

        assertEquals(oidcAgentConfig.getConsumerKey().getValue(), "KE4OYeY_gfYwzQbJa9tGhj1hZJMa");
        assertEquals(oidcAgentConfig.getConsumerSecret().getValue(), "_ebDU3prFV99JYgtbnknB0z0dXoa");
        assertTrue(oidcAgentConfig.getSkipURIs().contains("/oidc-sample-app/index.html"));
        assertEquals(oidcAgentConfig.getIndexPage(), "");
        assertEquals(oidcAgentConfig.getLogoutURL(), "logout");
        assertEquals(oidcAgentConfig.getCallbackUrl().toString(), "http://localhost:8080/oidc-sample-app/oauth2client");
        assertTrue(oidcAgentConfig.getScope().contains("openid"));
        assertTrue(oidcAgentConfig.getScope().contains("internal_application_mgt_view"));
        assertEquals(oidcAgentConfig.getAuthorizeEndpoint().toString(), "https://localhost:9443/oauth2/authorize");
        assertEquals(oidcAgentConfig.getLogoutEndpoint().toString(), "https://localhost:9443/oidc/logout");
        assertEquals(oidcAgentConfig.getTokenEndpoint().toString(), "https://localhost:9443/oauth2/token");
        assertEquals(oidcAgentConfig.getIssuer().toString(), "https://localhost:9443/oauth2/token");
        assertEquals(oidcAgentConfig.getJwksEndpoint().toString(), "https://localhost:9443/oauth2/jwks");
        assertEquals(oidcAgentConfig.getPostLogoutRedirectURI().toString(),
                "http://localhost:8080/oidc-sample-app/index.html");
    }
}