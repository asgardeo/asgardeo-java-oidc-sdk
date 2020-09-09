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

package io.asgardio.java.oidc.sdk;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.asgardio.java.oidc.sdk.bean.AuthenticationContext;
import io.asgardio.java.oidc.sdk.bean.OIDCAgentConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

public class OIDCManagerImpl implements OIDCManager {

    private static final Logger logger = LogManager.getLogger(OIDCManagerImpl.class);

    private OIDCAgentConfig oidcAgentConfig = null;

    public OIDCManagerImpl(OIDCAgentConfig oidcAgentConfig) {

        this.oidcAgentConfig = oidcAgentConfig;
    }

    @Override
    public void init() {

    }

    @Override
    public void login() {

    }

    @Override
    public AuthenticationContext authenticate() {

        return null;
    }

    @Override
    public void signOut() {

    }

    @Override
    public Map<String, Object> getUserInfo() {

        return null;
    }

    @Override
    public void validateAuthentication() {

    }

    @Override
    public AccessToken getAccessToken() {

        return null;
    }

    @Override
    public JWT getIDToken() {

        return null;
    }

    @Override
    public RefreshToken getRefreshToken() {

        return null;
    }

    @Override
    public void singleLogout() {

    }
}
