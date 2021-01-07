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

package io.asgardeo.java.oidc.sdk.exception;

import io.asgardeo.java.oidc.sdk.SSOAgentConstants;

import javax.servlet.ServletException;

/**
 * The {@code SSOAgentException} class is a generic
 * OIDC SDK exception class that provides type safety for all the
 * SDK-related exception classes that extend from it.
 * It is an implementation of the base class, {@link ServletException}.
 */
public class SSOAgentException extends ServletException {

    private static final long serialVersionUID = 2427874190311733363L;
    private String errorCode;

    public SSOAgentException() {

        super();
    }

    /**
     * Constructs a SSOAgentException with the specified detail
     * message. A detail message is a String that describes this
     * particular exception.
     *
     * @param message The detail message.
     */
    public SSOAgentException(String message) {

        super(message);
    }

    /**
     * Creates a {@code SSOAgentException} with the specified
     * detail message and cause.
     *
     * @param message   the detail message (which is saved for later retrieval
     *                  by the {@link #getMessage()} method).
     * @param errorCode The error code (which is saved for later retrieval by the
     *                  {@link #getErrorCode()} method).
     */
    public SSOAgentException(String message, String errorCode) {

        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Creates a {@code SSOAgentException} with the specified cause
     * and a detail message of {@code (cause==null ? null : cause.toString())}
     * (which typically contains the class and detail message of
     * {@code cause}).
     *
     * @param cause The cause (which is saved for later retrieval by the
     *              {@link #getCause()} method).
     */
    public SSOAgentException(Throwable cause) {

        super(cause);
    }

    /**
     * Creates a {@code SSOAgentException} with the specified
     * detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method).
     */
    public SSOAgentException(String message, Throwable cause) {

        super(message, cause);
    }

    /**
     * Creates a {@code SSOAgentException} with the specified
     * detail message and cause.
     *
     * @param message   the detail message (which is saved for later retrieval
     *                  by the {@link #getMessage()} method).
     * @param errorCode The error code (which is saved for later retrieval by the
     *                  {@link #getErrorCode()} method).
     * @param cause     the cause (which is saved for later retrieval by the
     *                  {@link #getCause()} method).
     */
    public SSOAgentException(String message, String errorCode, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Returns a {@code errorCode} for the exception as defined
     * in {@link SSOAgentConstants.ErrorMessages}.
     */
    public String getErrorCode() {

        return errorCode;
    }
}
