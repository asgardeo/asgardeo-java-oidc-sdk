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

import io.asgardio.java.oidc.sdk.bean.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;

import javax.servlet.ServletContext;

public class OIDCConfigProvider {

    private OIDCAgentConfig oidcAgentConfig = null;
    private final ServletContext servletContext;

    public OIDCConfigProvider(ServletContext servletContext) {

        this.servletContext = servletContext;
    }

    public void init() throws SSOAgentException {

        Object configBeanAttribute = servletContext.getAttribute(SSOAgentConstants.CONFIG_BEAN_NAME);

        if (!(configBeanAttribute instanceof OIDCAgentConfig)) {
            throw new SSOAgentException("Cannot find " + SSOAgentConstants.CONFIG_BEAN_NAME +
                    " attribute of OIDCAgentConfig type in the servletContext. Cannot proceed further.");
        }
        this.oidcAgentConfig = (OIDCAgentConfig) configBeanAttribute;
    }

    public OIDCAgentConfig getOidcAgentConfig() {

        return oidcAgentConfig;
    }
}
