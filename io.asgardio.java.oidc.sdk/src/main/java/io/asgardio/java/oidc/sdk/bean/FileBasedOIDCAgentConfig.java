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
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import io.asgardio.java.oidc.sdk.SSOAgentConstants;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

//file-based OIDC Agent Config
public class FileBasedOIDCAgentConfig implements OIDCAgentConfig, Serializable {

    private static final long serialVersionUID = 8862715306614922993L;

    private static final Logger logger = LogManager.getLogger(FileBasedOIDCAgentConfig.class);

    private ClientID consumerKey;
    private Secret consumerSecret;
    private String indexPage;
    private String logoutURL;
    private URI callbackUrl;
    private Scope scope;
    private State state;
    private URI authorizeEndpoint;
    private URI logoutEndpoint;
    private URI tokenEndpoint;
    private Issuer issuer;
    private URI jwksEndpoint;
    private URI postLogoutRedirectURI;
    private Set<String> skipURIs = new HashSet<String>();

    @Override
    public ClientID getConsumerKey() {

        return consumerKey;
    }

    @Override
    public void setConsumerKey(ClientID consumerKey) {

        this.consumerKey = consumerKey;

    }

    @Override
    public Secret getConsumerSecret() {

        return consumerSecret;
    }

    @Override
    public void setConsumerSecret(Secret consumerSecret) {

        this.consumerSecret = consumerSecret;
    }

    @Override
    public String getIndexPage() {

        return indexPage;
    }

    @Override
    public void setIndexPage(String indexPage) {

        this.indexPage = indexPage;
    }

    @Override
    public String getLogoutURL() {

        return logoutURL;
    }

    @Override
    public void setLogoutURL(String logoutURL) {

        this.logoutURL = logoutURL;
    }

    @Override
    public URI getCallbackUrl() {

        return callbackUrl;
    }

    @Override
    public void setCallbackUrl(URI callbackUrl) {

        this.callbackUrl = callbackUrl;
    }

    @Override
    public Scope getScope() {

        return scope;
    }

    @Override
    public void setScope(Scope scope) {

        this.scope = scope;
    }

    public State getState() {

        return state;
    }

    public void setState(State state) {

        this.state = state;
    }

    @Override
    public URI getAuthorizeEndpoint() {

        return authorizeEndpoint;
    }

    @Override
    public void setAuthorizeEndpoint(URI authorizeEndpoint) {

        this.authorizeEndpoint = authorizeEndpoint;
    }

    @Override
    public URI getLogoutEndpoint() {

        return logoutEndpoint;
    }

    @Override
    public void setLogoutEndpoint(URI logoutEndpoint) {

        this.logoutEndpoint = logoutEndpoint;
    }

    @Override
    public URI getTokenEndpoint() {

        return tokenEndpoint;
    }

    @Override
    public void setTokenEndpoint(URI tokenEndpoint) {

        this.tokenEndpoint = tokenEndpoint;
    }

    @Override
    public Issuer getIssuer() {

        return issuer;
    }

    @Override
    public void setIssuer(Issuer issuer) {

        this.issuer = issuer;
    }

    @Override
    public URI getJwksEndpoint() {

        return jwksEndpoint;
    }

    @Override
    public void setJwksEndpoint(URI jwksEndpoint) {

        this.jwksEndpoint = jwksEndpoint;
    }

    @Override
    public URI getPostLogoutRedirectURI() {

        return postLogoutRedirectURI;
    }

    @Override
    public void setPostLogoutRedirectURI(URI postLogoutRedirectURI) {

        this.postLogoutRedirectURI = postLogoutRedirectURI;
    }

    @Override
    public Set<String> getSkipURIs() {

        return skipURIs;
    }

    @Override
    public void setSkipURIs(Set<String> skipURIs) {

        this.skipURIs = skipURIs;
    }

    public FileBasedOIDCAgentConfig() {

    }

    @Override
    public void initConfig(Properties properties) throws SSOAgentClientException {

        consumerKey = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.CONSUMER_KEY)) ?
                new ClientID(properties.getProperty(SSOAgentConstants.CONSUMER_KEY)) : null;
        consumerSecret = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET)) ?
                new Secret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET)) : null;
        indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);
        logoutURL = properties.getProperty(SSOAgentConstants.LOGOUT_URL);
        try {
            callbackUrl = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.CALL_BACK_URL)) ?
                    new URI(properties.getProperty(SSOAgentConstants.CALL_BACK_URL)) : null;
            authorizeEndpoint =
                    StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT)) ?
                            new URI(properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT)) : null;
            logoutEndpoint = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT)) ?
                    new URI(properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT)) : null;
            tokenEndpoint = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT)) ?
                    new URI(properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT)) : null;
            issuer = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_ISSUER)) ?
                    new Issuer(properties.getProperty(SSOAgentConstants.OIDC_ISSUER)) : null;
            jwksEndpoint = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_JWKS_ENDPOINT)) ?
                    new URI(properties.getProperty(SSOAgentConstants.OIDC_JWKS_ENDPOINT)) : null;
            postLogoutRedirectURI =
                    StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI)) ?
                            new URI(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI)) : null;
        } catch (URISyntaxException e) {
            throw new SSOAgentClientException("URL not formatted properly.", e);
        }

        String scopeString = properties.getProperty(SSOAgentConstants.SCOPE);
        if (StringUtils.isNotBlank(scopeString)) {
            String[] scopeArray = scopeString.split(",");
            this.scope = new Scope(scopeArray);
        }

        String skipURIsString = properties.getProperty(SSOAgentConstants.SKIP_URIS);
        if (StringUtils.isNotBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }
        }
    }

    @Override
    public void initConfig(Map<String, String> oidcProperties) {

        consumerKey = new ClientID(oidcProperties.get("ClientId"));
        consumerSecret = new Secret(oidcProperties.get("ClientSecret"));
        scope = new Scope("openid");
//        state = new State(oidcProperties.get("state"));

        try {
            callbackUrl = new URI(oidcProperties.get("callbackUrl"));
            tokenEndpoint = new URI(oidcProperties.get("OAuth2TokenEPUrl"));
            authorizeEndpoint = new URI(oidcProperties.get("OAuth2AuthzEPUrl"));
            logoutEndpoint = StringUtils.isNotBlank(oidcProperties.get("OIDCLogoutEPUrl")) ?
                    new URI(oidcProperties.get("OIDCLogoutEPUrl")) : null;
            postLogoutRedirectURI = callbackUrl;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

    }
}
