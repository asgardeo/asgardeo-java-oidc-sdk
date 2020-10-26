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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

/**
 * A data model class to define the OIDC Agent Config element.
 */
public class OIDCAgentConfig {

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
    private Set<String> trustedAudience;
    private URI jwksEndpoint;
    private URI postLogoutRedirectURI;
    private JWSAlgorithm signatureAlgorithm;
    private Set<String> skipURIs = new HashSet<String>();

    /**
     * Returns the consumer key (Client ID) of the OIDC agent.
     *
     * @return {@link ClientID} of the OIDC agent.
     */
    public ClientID getConsumerKey() {

        return consumerKey;
    }

    /**
     * Sets the consumer key (Client ID) for the OIDC agent.
     *
     * @param consumerKey The consumer key of the OIDC agent.
     */
    public void setConsumerKey(ClientID consumerKey) {

        this.consumerKey = consumerKey;
    }

    /**
     * Returns the consumer secret (Client secret) of the OIDC agent.
     *
     * @return {@link Secret} of the OIDC agent.
     */
    public Secret getConsumerSecret() {

        return consumerSecret;
    }

    /**
     * Sets the consumer secret (Client secret) for the OIDC agent.
     *
     * @param consumerSecret The consumer secret of the OIDC agent.
     */
    public void setConsumerSecret(Secret consumerSecret) {

        this.consumerSecret = consumerSecret;
    }

    /**
     * Returns the index page of the OIDC agent.
     *
     * @return Index page of the OIDC agent.
     */
    public String getIndexPage() {

        return indexPage;
    }

    /**
     * Sets the index page for the OIDC agent.
     *
     * @param indexPage The index page of the OIDC agent.
     */
    public void setIndexPage(String indexPage) {

        this.indexPage = indexPage;
    }

    /**
     * Returns the logout URL of the OIDC agent.
     *
     * @return Logout URL of the OIDC agent.
     */
    public String getLogoutURL() {

        return logoutURL;
    }

    /**
     * Sets the logout URL for the OIDC agent.
     *
     * @param logoutURL The logout URL of the OIDC agent.
     */
    public void setLogoutURL(String logoutURL) {

        this.logoutURL = logoutURL;
    }

    /**
     * Returns the callback URI of the OIDC agent.
     *
     * @return Callback URI of the OIDC agent.
     */
    public URI getCallbackUrl() {

        return callbackUrl;
    }

    /**
     * Sets the callback URL for the OIDC agent.
     *
     * @param callbackUrl The callback URL of the OIDC agent.
     */
    public void setCallbackUrl(URI callbackUrl) {

        this.callbackUrl = callbackUrl;
    }

    /**
     * Returns the cscope of the OIDC agent.
     *
     * @return {@link Scope} of the OIDC agent.
     */
    public Scope getScope() {

        return scope;
    }

    /**
     * Sets the scope for the OIDC agent.
     *
     * @param scope The scope of the OIDC agent.
     */
    public void setScope(Scope scope) {

        this.scope = scope;
    }

    /**
     * Returns the authorize endpoint URI of the OIDC agent.
     *
     * @return The authorize endpoint URI of the OIDC agent.
     */
    public URI getAuthorizeEndpoint() {

        return authorizeEndpoint;
    }

    /**
     * Sets the authorize endpoint URL for the OIDC agent.
     *
     * @param authorizeEndpoint The authorize endpoint URL of the OIDC agent.
     */
    public void setAuthorizeEndpoint(URI authorizeEndpoint) {

        this.authorizeEndpoint = authorizeEndpoint;
    }

    /**
     * Returns the logout endpoint URI of the OIDC agent.
     *
     * @return The logout endpoint URI of the OIDC agent.
     */
    public URI getLogoutEndpoint() {

        return logoutEndpoint;
    }

    /**
     * Sets the logout endpoint URL for the OIDC agent.
     *
     * @param logoutEndpoint The logout endpoint URL of the OIDC agent.
     */
    public void setLogoutEndpoint(URI logoutEndpoint) {

        this.logoutEndpoint = logoutEndpoint;
    }

    /**
     * Returns the the token endpoint URI of the OIDC agent.
     *
     * @return The token endpoint URI of the OIDC agent.
     */
    public URI getTokenEndpoint() {

        return tokenEndpoint;
    }

    /**
     * Sets the token endpoint URL for the OIDC agent.
     *
     * @param tokenEndpoint The token endpoint URL of the OIDC agent.
     */
    public void setTokenEndpoint(URI tokenEndpoint) {

        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Returns the issuer of the OIDC agent.
     *
     * @return {@link Issuer} of the OIDC agent.
     */
    public Issuer getIssuer() {

        return issuer;
    }

    /**
     * Sets the issuer for the OIDC agent.
     *
     * @param issuer The issuer of the OIDC agent.
     */
    public void setIssuer(Issuer issuer) {

        this.issuer = issuer;
    }


    public Set<String> getTrustedAudience() {

        return trustedAudience;
    }

    public void setTrustedAudience(Set<String> trustedAudience) {

        this.trustedAudience = trustedAudience;
    }

    /**
     * Returns the JWKS endpoint URI of the OIDC agent.
     *
     * @return The JWKS endpoint URI of the OIDC agent.
     */
    public URI getJwksEndpoint() {

        return jwksEndpoint;
    }

    /**
     * Sets the JWKS endpoint URL for the OIDC agent.
     *
     * @param jwksEndpoint The JWKS endpoint URL of the OIDC agent.
     */
    public void setJwksEndpoint(URI jwksEndpoint) {

        this.jwksEndpoint = jwksEndpoint;
    }

    /**
     * Returns the post-logout redirect URI of the OIDC agent.
     *
     * @return The post-logout redirect URI of the OIDC agent.
     */
    public URI getPostLogoutRedirectURI() {

        return postLogoutRedirectURI;
    }

    /**
     * Sets the post-logout redirect URL for the OIDC agent.
     *
     * @param postLogoutRedirectURI The post-logout redirect URL of the OIDC agent.
     */
    public void setPostLogoutRedirectURI(URI postLogoutRedirectURI) {

        this.postLogoutRedirectURI = postLogoutRedirectURI;
    }

    public JWSAlgorithm getSignatureAlgorithm() {

        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(JWSAlgorithm signatureAlgorithm) {

        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Returns the skip URIs of the OIDC agent.
     *
     * @return The skip URIs of the OIDC agent.
     */
    public Set<String> getSkipURIs() {

        return skipURIs;
    }

    /**
     * Sets the skip URIs for the OIDC agent.
     *
     * @param skipURIs The skip URIs of the OIDC agent.
     */
    public void setSkipURIs(Set<String> skipURIs) {

        this.skipURIs = skipURIs;
    }
}
