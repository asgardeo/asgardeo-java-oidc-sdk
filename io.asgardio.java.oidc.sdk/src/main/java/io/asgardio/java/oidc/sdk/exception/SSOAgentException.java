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
 * This class is used to denote the exceptions thrown from the OIDC SSO agent module.
 */
public class SSOAgentException extends Exception {

    private static final long serialVersionUID = 2427874190311733363L;
    private String errorCode;

    public SSOAgentException() {

        super();
    }

    public SSOAgentException(String message) {

        super(message);
    }

    public SSOAgentException(String message, String errorCode) {

        super(message);
        this.errorCode = errorCode;
    }

    public SSOAgentException(Throwable cause) {

        super(cause);
    }

    public SSOAgentException(String message, Throwable cause) {

        super(message, cause);
    }

    public SSOAgentException(String message, String errorCode, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {

        return errorCode;
    }
}
