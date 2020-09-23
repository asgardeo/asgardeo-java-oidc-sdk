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

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import io.asgardio.java.oidc.sdk.bean.OIDCAgentConfig;
import org.apache.commons.lang.StringUtils;

import java.net.URI;

public class OIDCRequestBuilder {

    public static String buildAuthorizationRequest(String state, OIDCAgentConfig oidcAgentConfig) {

        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        ClientID clientID = oidcAgentConfig.getConsumerKey();
        Scope authScope = oidcAgentConfig.getScope();
        URI callBackURI = oidcAgentConfig.getCallbackUrl();
        URI authorizationEndpoint = oidcAgentConfig.getAuthorizeEndpoint();
        State stateParameter = null;
        if (StringUtils.isNotBlank(state)) {
            stateParameter = new State(state);
        }

        AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(responseType, clientID)
                .scope(authScope)
                .state(stateParameter)
                .redirectionURI(callBackURI)
                .endpointURI(authorizationEndpoint)
                .build();
        return authorizationRequest.toURI().toString();
    }

}
