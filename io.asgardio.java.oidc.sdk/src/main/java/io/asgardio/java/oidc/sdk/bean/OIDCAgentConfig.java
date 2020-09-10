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

public class OIDCAgentConfig {

    private static final Logger logger = LogManager.getLogger(OIDCAgentConfig.class);

    private ClientID consumerKey;
    private Secret consumerSecret;
    private String indexPage;
    private String logoutURL;
    private URI callbackUrl;
    private Scope scope;
    private URI authorizeEndpoint;
    private URI logoutEndpoint;
    private URI tokenEndpoint;
    private URI postLogoutRedirectURI;
    private Set<String> skipURIs = new HashSet<String>();

    public ClientID getConsumerKey() {

        return consumerKey;
    }

    public void setConsumerKey(ClientID consumerKey) {

        this.consumerKey = consumerKey;
    }

    public Secret getConsumerSecret() {

        return consumerSecret;
    }

    public void setConsumerSecret(Secret consumerSecret) {

        this.consumerSecret = consumerSecret;
    }

    public String getIndexPage() {

        return indexPage;
    }

    public void setIndexPage(String indexPage) {

        this.indexPage = indexPage;
    }

    public String getLogoutURL() {

        return logoutURL;
    }

    public void setLogoutURL(String logoutURL) {

        this.logoutURL = logoutURL;
    }

    public URI getCallbackUrl() {

        return callbackUrl;
    }

    public void setCallbackUrl(URI callbackUrl) {

        this.callbackUrl = callbackUrl;
    }

    public Scope getScope() {

        return scope;
    }

    public void setScope(Scope scope) {

        this.scope = scope;
    }

    public URI getAuthorizeEndpoint() {

        return authorizeEndpoint;
    }

    public void setAuthorizeEndpoint(URI authorizeEndpoint) {

        this.authorizeEndpoint = authorizeEndpoint;
    }

    public URI getLogoutEndpoint() {

        return logoutEndpoint;
    }

    public void setLogoutEndpoint(URI logoutEndpoint) {

        this.logoutEndpoint = logoutEndpoint;
    }

    public URI getTokenEndpoint() {

        return tokenEndpoint;
    }

    public void setTokenEndpoint(URI tokenEndpoint) {

        this.tokenEndpoint = tokenEndpoint;
    }

    public URI getPostLogoutRedirectURI() {

        return postLogoutRedirectURI;
    }

    public void setPostLogoutRedirectURI(URI postLogoutRedirectURI) {

        this.postLogoutRedirectURI = postLogoutRedirectURI;
    }

    public Set<String> getSkipURIs() {

        return skipURIs;
    }

    public void setSkipURIs(Set<String> skipURIs) {

        this.skipURIs = skipURIs;
    }

    public OIDCAgentConfig() {

    }

    public void initConfig(Properties properties) throws SSOAgentClientException {

        consumerKey = new ClientID(properties.getProperty(SSOAgentConstants.CONSUMER_KEY));
        consumerSecret = new Secret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET));
        indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);
        logoutURL = properties.getProperty(SSOAgentConstants.LOGOUT_URL);

        try {
            callbackUrl = new URI(properties.getProperty(SSOAgentConstants.CALL_BACK_URL));
            authorizeEndpoint = new URI(properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT));
            logoutEndpoint = new URI(properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT));
            tokenEndpoint = new URI(properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT));
            postLogoutRedirectURI = new URI(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI));
        } catch (URISyntaxException e) {
            throw new SSOAgentClientException("URL not formatted properly.", e);
        }

//        String scopeString = properties.getProperty(SSOAgentConstants.SCOPE);
//        if (StringUtils.isNotBlank(scopeString)) {
//            String[] scopeArray = scopeString.split(",");
//            this.scope = new Scope(scopeArray);

//            String[] scopes = (String[]) Stream
//                    .of(scopeString.split(","))
//                    .toArray();
//            this.scope = new Scope(scopes);
//        }

        String skipURIsString = properties.getProperty(SSOAgentConstants.SKIP_URIS);
        if (StringUtils.isNotBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }

//            skipURIs = Stream
//                    .of(skipURIsString.split(","))
//                    .collect(Collectors.toSet());
        }

    }
}
