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

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import io.asgardio.java.oidc.sdk.SSOAgentConstants;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * A file-based provider implementation for the {@link OIDCAgentConfig} model.
 * It is an implementation of the base class, {@link OIDCConfigProvider}.
 */
public class FileBasedOIDCConfigProvider implements OIDCConfigProvider {

    private static final Logger logger = LogManager.getLogger(FileBasedOIDCConfigProvider.class);

    private final OIDCAgentConfig oidcAgentConfig = new OIDCAgentConfig();

    public FileBasedOIDCConfigProvider(InputStream fileInputStream) throws SSOAgentClientException {

        Properties properties = new Properties();
        try {
            properties.load(fileInputStream);
        } catch (IOException e) {
            logger.log(Level.FATAL, "Error while loading properties.", e);
        }
        initConfig(properties);
    }

    private void initConfig(Properties properties) throws SSOAgentClientException {

        ClientID consumerKey = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.CONSUMER_KEY)) ?
                new ClientID(properties.getProperty(SSOAgentConstants.CONSUMER_KEY)) : null;
        Secret consumerSecret = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET)) ?
                new Secret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET)) : null;
        String indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);
        String logoutURL = properties.getProperty(SSOAgentConstants.LOGOUT_URL);
        try {
            URI callbackUrl = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.CALL_BACK_URL)) ?
                    new URI(properties.getProperty(SSOAgentConstants.CALL_BACK_URL)) : null;
            URI authorizeEndpoint =
                    StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT)) ?
                            new URI(properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT)) : null;
            URI logoutEndpoint =
                    StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT)) ?
                            new URI(properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT)) : null;
            URI tokenEndpoint = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT)) ?
                    new URI(properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT)) : null;
            URI jwksEndpoint = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_JWKS_ENDPOINT)) ?
                    new URI(properties.getProperty(SSOAgentConstants.OIDC_JWKS_ENDPOINT)) : null;
            URI postLogoutRedirectURI =
                    StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI)) ?
                            new URI(properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI)) :
                            callbackUrl;
            oidcAgentConfig.setCallbackUrl(callbackUrl);
            oidcAgentConfig.setAuthorizeEndpoint(authorizeEndpoint);
            oidcAgentConfig.setLogoutEndpoint(logoutEndpoint);
            oidcAgentConfig.setTokenEndpoint(tokenEndpoint);
            oidcAgentConfig.setJwksEndpoint(jwksEndpoint);
            oidcAgentConfig.setPostLogoutRedirectURI(postLogoutRedirectURI);
        } catch (URISyntaxException e) {
            throw new SSOAgentClientException("URL not formatted properly.", e);
        }

        Issuer issuer = StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.OIDC_ISSUER)) ?
                new Issuer(properties.getProperty(SSOAgentConstants.OIDC_ISSUER)) : null;
        String scopeString = properties.getProperty(SSOAgentConstants.SCOPE);
        if (StringUtils.isNotBlank(scopeString)) {
            String[] scopeArray = scopeString.split(",");
            Scope scope = new Scope(scopeArray);
            oidcAgentConfig.setScope(scope);
        }

        Set<String> skipURIs = new HashSet<String>();
        String skipURIsString = properties.getProperty(SSOAgentConstants.SKIP_URIS);
        if (StringUtils.isNotBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }
        }
        oidcAgentConfig.setConsumerKey(consumerKey);
        oidcAgentConfig.setConsumerSecret(consumerSecret);
        oidcAgentConfig.setIndexPage(indexPage);
        oidcAgentConfig.setLogoutURL(logoutURL);
        oidcAgentConfig.setIssuer(issuer);
        oidcAgentConfig.setSkipURIs(skipURIs);
    }

    /**
     * {@inheritDoc}
     */
    public OIDCAgentConfig getOidcAgentConfig() {

        return oidcAgentConfig;
    }
}
