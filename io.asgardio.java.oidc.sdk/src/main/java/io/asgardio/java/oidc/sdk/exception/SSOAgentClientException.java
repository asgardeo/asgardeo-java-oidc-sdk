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
 * Client exception class for the Java OIDC SDK.
 *
 * @version 0.1.1
 * @since 0.1.1
 */
public class SSOAgentClientException extends SSOAgentException {

    private static final long serialVersionUID = 7038967084217855809L;

    /**
     * Constructs a SSOAgentClientException with the specified detail
     * message. A detail message is a String that describes this
     * particular exception.
     *
     * @param message The detail message.
     */
    public SSOAgentClientException(String message) {

        super(message);
    }

    /**
     * Creates a {@code SSOAgentClientException} with the specified
     * detail message and cause.

     * @param message the detail message (which is saved for later retrieval
     *        by the {@link #getMessage()} method).
     * @param errorCode The error code (which is saved for later retrieval by the
     *        {@link #getErrorCode()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).
     */
    public SSOAgentClientException(String message, String errorCode, Throwable cause) {

        super(message, errorCode, cause);
    }

    /**
     * Creates a {@code SSOAgentClientException} with the specified
     * detail message and cause.
     *
     * @param message The detail message (which is saved for later retrieval
     *        by the {@link #getMessage()} method).
     *
     * @param cause The cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).
     */
    public SSOAgentClientException(String message, Throwable cause) {

        super(message, cause);
    }

    /**
     * Creates a {@code SSOAgentClientException} with the specified
     * detail message and cause.
     *
     * @param message The detail message (which is saved for later retrieval
     *        by the {@link #getMessage()} method).
     * @param errorCode The error code (which is saved for later retrieval by the
     *        {@link #getErrorCode()} method).
     */
    public SSOAgentClientException(String message, String errorCode) {

        super(message, errorCode);
    }
}
