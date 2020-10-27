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

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * A data model class to define the Request Context element. The Request Context object
 * should be used to hold the attributes regarding the authentication flow. These include the attributes:
 * <ul>
 * <li>The state parameter
 * <li>The nonce value
 * <li>Additional custom parameters
 * </ul>
 * <p>
 * The Request Context and its attributes would be used from the initiation of the authentication
 * request until the authentication completion of the user.
 */
public class RequestContext implements Serializable {

    private static final long serialVersionUID = -3980859739213942559L;

    private State state;
    private Nonce nonce;
    private Map<String, Object> additionalParams = new HashMap<>();

    public RequestContext(State state, Nonce nonce) {

        this.state = state;
        this.nonce = nonce;
    }

    public State getState() {

        return state;
    }

    public void setState(State state) {

        this.state = state;
    }

    public Nonce getNonce() {

        return nonce;
    }

    public void setNonce(Nonce nonce) {

        this.nonce = nonce;
    }

    public Object getParameter(String key) {

        return additionalParams.get(key);
    }

    public void setParameter(String key, Object value) {

        additionalParams.put(key, value);
    }
}
