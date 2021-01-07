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

package io.asgardeo.java.oidc.sdk.request.model;

import io.asgardeo.java.oidc.sdk.bean.RequestContext;

import java.io.Serializable;
import java.net.URI;

/**
 * A data model class to define the Logout Request element.
 */
public class LogoutRequest implements Serializable {

    private static final long serialVersionUID = 6184960293632714833L;

    private URI logoutRequestURI;
    private RequestContext requestContext;

    public LogoutRequest(URI logoutRequestURI, RequestContext requestContext) {

        this.logoutRequestURI = logoutRequestURI;
        this.requestContext = requestContext;
    }

    public URI getLogoutRequestURI() {

        return logoutRequestURI;
    }

    public void setLogoutRequestURI(URI logoutRequestURI) {

        this.logoutRequestURI = logoutRequestURI;
    }

    public RequestContext getRequestContext() {

        return requestContext;
    }

    public void setRequestContext(RequestContext requestContext) {

        this.requestContext = requestContext;
    }
}
