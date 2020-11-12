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

    public RequestContext() {

    }

    /**
     * Returns the state.
     *
     * @return {@link State} object for the request.
     */
    public State getState() {

        return state;
    }

    /**
     * Sets the state.
     *
     * @param state The state object.
     */
    public void setState(State state) {

        this.state = state;
    }

    /**
     * Returns the nonce.
     *
     * @return {@link Nonce} object for the request.
     */
    public Nonce getNonce() {

        return nonce;
    }

    /**
     * Sets the nonce.
     *
     * @param nonce The nonce object.
     */
    public void setNonce(Nonce nonce) {

        this.nonce = nonce;
    }

    /**
     * Returns the object for the particular key.
     *
     * @param key The String value of the key.
     * @return The additional parameter object in the request for the particular key.
     */
    public Object getParameter(String key) {

        return additionalParams.get(key);
    }

    /**
     * Sets additional parameter to the Request Context.
     *
     * @param key   The key of the parameter.
     * @param value The value of the parameter.
     */
    public void setParameter(String key, Object value) {

        additionalParams.put(key, value);
    }
}
