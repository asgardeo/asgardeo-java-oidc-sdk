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

import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;

/**
 * A factory to create Default OIDC Manger objects based on a OIDCAgentConfig.
 */
public class DefaultOIDCManagerFactory {

    /**
     * Creates a new {@link DefaultOIDCManager} object.
     *
     * @param oidcAgentConfig The {@link OIDCAgentConfig} object containing the client specific details.
     * @return The DefaultOIDCManager instance.
     * @throws SSOAgentClientException If the OIDCAgentConfig validation is unsuccessful.
     */
    public static OIDCManager createOIDCManager(OIDCAgentConfig oidcAgentConfig) throws SSOAgentClientException {

        return new DefaultOIDCManager(oidcAgentConfig);
    }
}
