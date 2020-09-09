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

package io.asgardio.java.oidc.sdk.bean;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import io.asgardio.java.oidc.sdk.SSOAgentConstants;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class OIDCAgentConfig {

    private static final Logger logger = LogManager.getLogger(OIDCAgentConfig.class);

    private static ClientID consumerKey;
    private static Secret consumerSecret;
    private static String indexPage;
    private static URI callbackUrl;
    private static Scope scope;
    private static URI authorizeEndpoint;
    private static URI logoutEndpoint;
    private static URI tokenEndpoint;
    private static URI postLogoutRedirectURI;
    private static Set<String> skipURIs = new HashSet<String>();

    public OIDCAgentConfig() {

    }

    public void initConfig(Properties properties) throws SSOAgentClientException {

        consumerKey = new ClientID(properties.getProperty(SSOAgentConstants.CONSUMER_KEY));
        consumerSecret = new Secret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET));
        indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);

        try {
            callbackUrl = new URI(properties.getProperty(SSOAgentConstants.CALL_BACK_URL));
            authorizeEndpoint = new URI(properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT));
            logoutEndpoint = new URI(properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT));
            tokenEndpoint = new URI(properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT));
            postLogoutRedirectURI = new URI(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI));
        } catch (URISyntaxException e) {
            throw new SSOAgentClientException("URL not formatted properly.", e);
        }

        String scopeString = properties.getProperty(SSOAgentConstants.SCOPE);
    if (StringUtils.isNotBlank(scopeString)) {
            String[] scopes = (String[]) Stream
                    .of(scopeString.split(","))
                    .toArray();
            scope = new Scope(scopes);
        }

        String skipURIsString = properties.getProperty(SSOAgentConstants.SKIP_URIS);
        if (StringUtils.isNotBlank(skipURIsString)) {
            skipURIs = Stream
                    .of(skipURIsString.split(","))
                    .collect(Collectors.toSet());
        }

    }
}
