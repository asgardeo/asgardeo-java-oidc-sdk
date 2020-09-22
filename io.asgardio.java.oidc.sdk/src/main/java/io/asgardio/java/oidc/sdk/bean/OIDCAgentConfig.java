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
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;

import java.net.URI;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public interface OIDCAgentConfig {

    /**
     * Reads the properties from a source and sets them to class parameters.
     *
     * @param properties {@link Properties} of the client application.
     */
    public void initConfig(Properties properties) throws SSOAgentClientException;

    public void initConfig(Map<String, String> oidcProperties);

    /**
     * Returns the consumer key.
     *
     * @return {@link ClientID} of the client application.
     */
    public ClientID getConsumerKey();

    /**
     * Sets the consumer key.
     *
     * @param consumerKey {@link ClientID} of the client application.
     */
    public void setConsumerKey(ClientID consumerKey);

    /**
     * Returns the consumer secret.
     *
     * @return {@link Secret} client secret of the application.
     */
    public Secret getConsumerSecret();

    /**
     * Sets the consumer secret.
     *
     * @param consumerSecret {@link Secret} of the client application.
     */
    public void setConsumerSecret(Secret consumerSecret);

    /**
     * Returns the index page.
     *
     * @return Index page of the application.
     */
    public String getIndexPage();

    /**
     * Sets the index page.
     *
     * @param indexPage Index page of the client application.
     */
    public void setIndexPage(String indexPage);

    /**
     * Returns the logout URL.
     *
     * @return Logout URL of the application.
     */
    public String getLogoutURL();

    /**
     * Sets the logout URL.
     *
     * @param logoutURL Logout URL of the client application.
     */
    public void setLogoutURL(String logoutURL);

    /**
     * Returns the callback URL.
     *
     * @return Callback URL of the application.
     */
    public URI getCallbackUrl();

    /**
     * Sets the callback URL.
     *
     * @param callbackUrl Callback URL of the client application.
     */
    public void setCallbackUrl(URI callbackUrl);

    /**
     * Returns the scope.
     *
     * @return {@link Scope} Scope of the application.
     */
    public Scope getScope();

    /**
     * Sets the scope.
     *
     * @param scope {@link Scope} of the client application.
     */
    public void setScope(Scope scope);

    public State getState();

    public void setState(State state);

    /**
     * Returns the authorize endpoint.
     *
     * @return Authorize endpoint of the OIDC provider.
     */
    public URI getAuthorizeEndpoint();

    /**
     * Sets the authorize endpoint.
     *
     * @param authorizeEndpoint Authorize endpoint of the OIDC provider.
     */
    public void setAuthorizeEndpoint(URI authorizeEndpoint);

    /**
     * Returns the logout endpoint.
     *
     * @return Logout endpoint of the OIDC provider.
     */
    public URI getLogoutEndpoint();

    /**
     * Sets the logout endpoint.
     *
     * @param logoutEndpoint Logout endpoint of the OIDC provider.
     */
    public void setLogoutEndpoint(URI logoutEndpoint);

    /**
     * Returns the token endpoint.
     *
     * @return Token endpoint of the OIDC provider.
     */
    public URI getTokenEndpoint();

    /**
     * Sets the token endpoint.
     *
     * @param tokenEndpoint Token endpoint of the OIDC provider.
     */
    public void setTokenEndpoint(URI tokenEndpoint);

    /**
     * Returns the issuer ID.
     *
     * @return {@link Issuer} Issuer ID of the OIDC provider.
     */
    public Issuer getIssuer();

    /**
     * Sets the issuer ID.
     *
     * @param issuer {@link Issuer} Issuer ID of the OIDC provider.
     */
    public void setIssuer(Issuer issuer);

    /**
     * Returns the JWKS endpoint.
     *
     * @return JWKS endpoint of the OIDC provider.
     */
    public URI getJwksEndpoint();

    /**
     * Sets the JWKS endpoint.
     *
     * @param jwksEndpoint JWKS endpoint of the OIDC provider.
     */
    public void setJwksEndpoint(URI jwksEndpoint);

    /**
     * Returns the post logout redirect URI.
     *
     * @return Post logout redirect URI of the application.
     */
    public URI getPostLogoutRedirectURI();

    /**
     * Sets the post logout redirect URI.
     *
     * @param postLogoutRedirectURI Post logout redirect URI of the application.
     */
    public void setPostLogoutRedirectURI(URI postLogoutRedirectURI);

    /**
     * Returns the skip URIs.
     *
     * @return Skip URIs of the application.
     */
    public Set<String> getSkipURIs();

    /**
     * Sets the skip URIs.
     *
     * @param skipURIs The set of application pages which need not be secured.
     */
    public void setSkipURIs(Set<String> skipURIs);
}
