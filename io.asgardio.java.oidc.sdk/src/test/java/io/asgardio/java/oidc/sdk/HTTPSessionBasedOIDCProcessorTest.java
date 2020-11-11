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

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import io.asgardio.java.oidc.sdk.bean.RequestContext;
import io.asgardio.java.oidc.sdk.bean.SessionContext;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentClientException;
import io.asgardio.java.oidc.sdk.exception.SSOAgentException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@PrepareForTest({DefaultOIDCManager.class, DefaultOIDCManagerFactory.class})
public class HTTPSessionBasedOIDCProcessorTest extends PowerMockTestCase {

    @Mock
    DefaultOIDCManager defaultOIDCManager;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    OIDCAgentConfig oidcAgentConfig = new OIDCAgentConfig();

    private static MockedStatic<DefaultOIDCManagerFactory> mockedOIDCManagerFactory;

    @BeforeMethod
    public void setUp() throws Exception {

        defaultOIDCManager = mock(DefaultOIDCManager.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
    }

    @AfterMethod
    public void tearDown() {

        mockedOIDCManagerFactory.close();
    }

    @Test
    public void testSendForLogin() throws Exception {

        Nonce nonce = new Nonce();
        State state = new State("SampleState");
        RequestContext requestContext = new RequestContext(state, nonce);

        HttpSession session = mock(HttpSession.class);
        mockedOIDCManagerFactory = mockStatic(DefaultOIDCManagerFactory.class);
        when(DefaultOIDCManagerFactory.createOIDCManager(oidcAgentConfig)).thenReturn(defaultOIDCManager);
        when(request.getSession()).thenReturn(session);
        when(defaultOIDCManager.sendForLogin(request, response)).thenReturn(requestContext);

        HTTPSessionBasedOIDCProcessor provider = new HTTPSessionBasedOIDCProcessor(oidcAgentConfig);
        provider.sendForLogin(request, response);

        verify(session).setAttribute(SSOAgentConstants.REQUEST_CONTEXT, requestContext);
    }

    @Test
    public void testHandleOIDCCallback() throws SSOAgentException {

        SessionContext sessionContext = new SessionContext();
        RequestContext requestContext = new RequestContext();

        HttpSession session = mock(HttpSession.class);
        mockedOIDCManagerFactory = mockStatic(DefaultOIDCManagerFactory.class);
        when(DefaultOIDCManagerFactory.createOIDCManager(oidcAgentConfig)).thenReturn(defaultOIDCManager);
        when(request.getSession()).thenReturn(session);
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(SSOAgentConstants.REQUEST_CONTEXT)).thenReturn(requestContext);
        when(defaultOIDCManager.handleOIDCCallback(request, response, requestContext)).thenReturn(sessionContext);

        HTTPSessionBasedOIDCProcessor provider = new HTTPSessionBasedOIDCProcessor(oidcAgentConfig);
        provider.handleOIDCCallback(request, response);

        verify(session).setAttribute(SSOAgentConstants.SESSION_CONTEXT, sessionContext);
    }

    @Test
    public void testLogout() throws SSOAgentException {

        RequestContext requestContext = new RequestContext();
        SessionContext sessionContext = new SessionContext();

        HttpSession session = mock(HttpSession.class);
        mockedOIDCManagerFactory = mockStatic(DefaultOIDCManagerFactory.class);
        when(DefaultOIDCManagerFactory.createOIDCManager(oidcAgentConfig)).thenReturn(defaultOIDCManager);
        when(request.getSession()).thenReturn(session);
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(SSOAgentConstants.SESSION_CONTEXT)).thenReturn(sessionContext);
        when(defaultOIDCManager.logout(sessionContext, response)).thenReturn(requestContext);

        HTTPSessionBasedOIDCProcessor provider = new HTTPSessionBasedOIDCProcessor(oidcAgentConfig);
        provider.logout(request, response);

        verify(session).setAttribute(SSOAgentConstants.REQUEST_CONTEXT, requestContext);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
