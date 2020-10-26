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

import java.io.Serializable;
import java.net.URI;

/**
 * A data model class to define the Authentication Request element.
 */
public class AuthenticationRequest implements Serializable {

    private static final long serialVersionUID = 7931793096680065576L;

    private URI authenticationRequestURI;
    private RequestContext requestContext;

    public AuthenticationRequest(URI authenticationRequestURI, RequestContext requestContext) {

        this.authenticationRequestURI = authenticationRequestURI;
        this.requestContext = requestContext;
    }

    public URI getAuthenticationRequestURI() {

        return authenticationRequestURI;
    }

    public void setAuthenticationRequestURI(URI authenticationRequestURI) {

        this.authenticationRequestURI = authenticationRequestURI;
    }

    public RequestContext getRequestContext() {

        return requestContext;
    }

    public void setRequestContext(RequestContext requestContext) {

        this.requestContext = requestContext;
    }
}
