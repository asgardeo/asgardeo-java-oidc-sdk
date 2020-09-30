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

package io.asgardio.java.oidc.sdk.exception;

/**
 * This class is used to denote the client exceptions thrown from the OIDC SSO agent module.
 */
public class SSOAgentClientException extends SSOAgentException {

    private static final long serialVersionUID = 7038967084217855809L;

    public SSOAgentClientException(String message) {

        super(message);
    }

    public SSOAgentClientException(String message, String errorCode, Throwable cause) {

        super(message, errorCode, cause);
    }

    public SSOAgentClientException(String message, Throwable cause) {

        super(message, cause);
    }

    public SSOAgentClientException(String message, String errorCode) {

        super(message, errorCode);
    }
}
