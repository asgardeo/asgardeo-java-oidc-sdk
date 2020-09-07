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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

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
    private final Set<String> skipURIs = new HashSet<String>();

    private OIDCAgentConfig() {

    }

    public static void initConfig(Properties properties) {

        consumerKey = new ClientID(properties.getProperty(SSOAgentConstants.CONSUMER_KEY));
        consumerSecret = new Secret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET));

    }
}
