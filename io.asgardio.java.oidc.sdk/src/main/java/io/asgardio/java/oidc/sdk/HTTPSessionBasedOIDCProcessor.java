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

import io.asgardio.java.oidc.sdk.bean.RequestContext;
import io.asgardio.java.oidc.sdk.bean.SessionContext;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * A wrapper class for the {@link DefaultOIDCManager} that provides
 * the functionality defined by the {@link OIDCManager} with using
 * HTTP sessions as the storage entity for the {@link RequestContext}
 * and {@link SessionContext} information.
 */
public class HTTPSessionBasedOIDCProcessor {

    private static final Logger logger = LogManager.getLogger(HTTPSessionBasedOIDCProcessor.class);

    private final OIDCManager defaultOIDCManager;

    public HTTPSessionBasedOIDCProcessor(OIDCAgentConfig oidcAgentConfig) throws SSOAgentClientException {

        defaultOIDCManager = DefaultOIDCManagerFactory.createOIDCManager(oidcAgentConfig);
    }

    /**
     * Builds an authentication request and redirects. Information
     * regarding the authentication session would be retrieved via
     * {@link RequestContext} object and then, would be written to
     * the http session.
     *
     * @param request  Incoming {@link HttpServletRequest}.
     * @param response Outgoing {@link HttpServletResponse}.
     * @throws SSOAgentException
     */
    public void sendForLogin(HttpServletRequest request, HttpServletResponse response)
            throws SSOAgentException {

        HttpSession session = request.getSession();
        RequestContext requestContext = defaultOIDCManager.sendForLogin(request, response);
        session.setAttribute(SSOAgentConstants.REQUEST_CONTEXT, requestContext);
    }

    /**
     * Processes the OIDC callback response and extract the authorization
     * code, builds a token request, sends the token request and parse
     * the token response where the authenticated user info and tokens
     * would be added to the {@link SessionContext} object and written
     * into the available http session.
     *
     * @param request  Incoming {@link HttpServletRequest}.
     * @param response Outgoing {@link HttpServletResponse}.
     * @throws SSOAgentException Upon failed authentication.
     */
    public void handleOIDCCallback(HttpServletRequest request, HttpServletResponse response) throws SSOAgentException {

        RequestContext requestContext = getRequestContext(request);
        clearSession(request);
        SessionContext sessionContext = defaultOIDCManager.handleOIDCCallback(request, response, requestContext);

        if (sessionContext != null) {
            clearSession(request);
            HttpSession session = request.getSession();
            session.setAttribute(SSOAgentConstants.SESSION_CONTEXT, sessionContext);
        } else {
            throw new SSOAgentServerException("Null session context.");
        }
    }

    /**
     * Builds a logout request and redirects.
     *
     * @param request  Incoming {@link HttpServletRequest}.
     * @param response Outgoing {@link HttpServletResponse}
     * @throws SSOAgentException
     */
    public void logout(HttpServletRequest request, HttpServletResponse response) throws SSOAgentException {

        SessionContext sessionContext = getSessionContext(request);
        clearSession(request);
        RequestContext requestContext = defaultOIDCManager.logout(sessionContext, response);
        HttpSession session = request.getSession();
        session.setAttribute(SSOAgentConstants.REQUEST_CONTEXT, requestContext);
    }

    private void clearSession(HttpServletRequest request) {

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }
    }

    private RequestContext getRequestContext(HttpServletRequest request) throws SSOAgentServerException {

        HttpSession session = request.getSession(false);

        if (session != null && session.getAttribute(SSOAgentConstants.REQUEST_CONTEXT) != null) {
            return (RequestContext) request.getSession(false)
                    .getAttribute(SSOAgentConstants.REQUEST_CONTEXT);
        }
        throw new SSOAgentServerException("Request context null.");
    }

    private SessionContext getSessionContext(HttpServletRequest request) throws SSOAgentServerException {

        HttpSession session = request.getSession(false);

        if (session != null && session.getAttribute(SSOAgentConstants.SESSION_CONTEXT) != null) {
            return (SessionContext) request.getSession(false)
                    .getAttribute(SSOAgentConstants.SESSION_CONTEXT);
        }
        throw new SSOAgentServerException("Session context null.");
    }
}
