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
import io.asgardio.java.oidc.sdk.SSOAgentConstants;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

//file-based OIDC Agent Config
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
    private Issuer issuer;
    private URI jwksEndpoint;
    private URI postLogoutRedirectURI;
    private Set<String> skipURIs = new HashSet<String>();

    /**
     * Returns the consumer key.
     *
     * @return {@link ClientID} of the client application.
     */
    public ClientID getConsumerKey() {

        return consumerKey;
    }

    /**
     * Sets the consumer key.
     *
     * @param consumerKey {@link ClientID} of the client application.
     */
    public void setConsumerKey(ClientID consumerKey) {

        this.consumerKey = consumerKey;
    }

    /**
     * Returns the consumer secret.
     *
     * @return {@link Secret} client secret of the application.
     */
    public Secret getConsumerSecret() {

        return consumerSecret;
    }

    /**
     * Sets the consumer secret.
     *
     * @param consumerSecret {@link Secret} of the client application.
     */
    public void setConsumerSecret(Secret consumerSecret) {

        this.consumerSecret = consumerSecret;
    }

    /**
     * Returns the index page.
     *
     * @return Index page of the application.
     */
    public String getIndexPage() {

        return indexPage;
    }

    /**
     * Sets the index page.
     *
     * @param indexPage Index page of the client application.
     */
    public void setIndexPage(String indexPage) {

        this.indexPage = indexPage;
    }

    /**
     * Returns the logout URL.
     *
     * @return Logout URL of the application.
     */
    public String getLogoutURL() {

        return logoutURL;
    }

    /**
     * Sets the logout URL.
     *
     * @param logoutURL Logout URL of the client application.
     */
    public void setLogoutURL(String logoutURL) {

        this.logoutURL = logoutURL;
    }

    /**
     * Returns the callback URL.
     *
     * @return Callback URL of the application.
     */
    public URI getCallbackUrl() {

        return callbackUrl;
    }

    /**
     * Sets the callback URL.
     *
     * @param callbackUrl Callback URL of the client application.
     */
    public void setCallbackUrl(URI callbackUrl) {

        this.callbackUrl = callbackUrl;
    }

    /**
     * Returns the scope.
     *
     * @return {@link Scope} Scope of the application.
     */
    public Scope getScope() {

        return scope;
    }

    /**
     * Sets the scope.
     *
     * @param scope {@link Scope} of the client application.
     */
    public void setScope(Scope scope) {

        this.scope = scope;
    }

    /**
     * Returns the authorize endpoint.
     *
     * @return Authorize endpoint of the OIDC provider.
     */
    public URI getAuthorizeEndpoint() {

        return authorizeEndpoint;
    }

    /**
     * Sets the authorize endpoint.
     *
     * @param authorizeEndpoint Authorize endpoint of the OIDC provider.
     */
    public void setAuthorizeEndpoint(URI authorizeEndpoint) {

        this.authorizeEndpoint = authorizeEndpoint;
    }

    /**
     * Returns the logout endpoint.
     *
     * @return Logout endpoint of the OIDC provider.
     */
    public URI getLogoutEndpoint() {

        return logoutEndpoint;
    }

    /**
     * Sets the logout endpoint.
     *
     * @param logoutEndpoint Logout endpoint of the OIDC provider.
     */
    public void setLogoutEndpoint(URI logoutEndpoint) {

        this.logoutEndpoint = logoutEndpoint;
    }

    /**
     * Returns the token endpoint.
     *
     * @return Token endpoint of the OIDC provider.
     */
    public URI getTokenEndpoint() {

        return tokenEndpoint;
    }

    /**
     * Sets the token endpoint.
     *
     * @param tokenEndpoint Token endpoint of the OIDC provider.
     */
    public void setTokenEndpoint(URI tokenEndpoint) {

        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Returns the issuer ID.
     *
     * @return {@link Issuer} Issuer ID of the OIDC provider.
     */
    public Issuer getIssuer() {

        return issuer;
    }

    /**
     * Sets the issuer ID.
     *
     * @param issuer {@link Issuer} Issuer ID of the OIDC provider.
     */
    public void setIssuer(Issuer issuer) {

        this.issuer = issuer;
    }

    /**
     * Returns the JWKS endpoint.
     *
     * @return JWKS endpoint of the OIDC provider.
     */
    public URI getJwksEndpoint() {

        return jwksEndpoint;
    }

    /**
     * Sets the JWKS endpoint.
     *
     * @param jwksEndpoint JWKS endpoint of the OIDC provider.
     */
    public void setJwksEndpoint(URI jwksEndpoint) {

        this.jwksEndpoint = jwksEndpoint;
    }

    /**
     * Returns the post logout redirect URI.
     *
     * @return Post logout redirect URI of the application.
     */
    public URI getPostLogoutRedirectURI() {

        return postLogoutRedirectURI;
    }

    /**
     * Sets the post logout redirect URI.
     *
     * @param postLogoutRedirectURI Post logout redirect URI of the application.
     */
    public void setPostLogoutRedirectURI(URI postLogoutRedirectURI) {

        this.postLogoutRedirectURI = postLogoutRedirectURI;
    }

    /**
     * Returns the skip URIs.
     *
     * @return Skip URIs of the application.
     */
    public Set<String> getSkipURIs() {

        return skipURIs;
    }

    /**
     * Sets the skip URIs.
     *
     * @param skipURIs The set of application pages which need not be secured.
     */
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
            issuer = new Issuer(properties.getProperty(SSOAgentConstants.OIDC_ISSUER));
            jwksEndpoint = new URI(properties.getProperty(SSOAgentConstants.OIDC_JWKS_ENDPOINT));
            postLogoutRedirectURI = new URI(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI));
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

    public void initConfig(Map<String, String> oidcProperties) {

        consumerKey = new ClientID(oidcProperties.get("ClientId"));
        consumerSecret = new Secret(oidcProperties.get("ClientSecret"));
        scope = new Scope("openid");

        try {
            callbackUrl = new URI(oidcProperties.get("callbackUrl"));
            tokenEndpoint = new URI(oidcProperties.get("OAuth2TokenEPUrl"));
            authorizeEndpoint = new URI(oidcProperties.get("OAuth2AuthzEPUrl"));
            logoutEndpoint = new URI(oidcProperties.get("OIDCLogoutEPUrl"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

    }
}
