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

package io.asgardio.java.oidc.sdk.util;

import io.asgardio.java.oidc.sdk.bean.TokenData;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * This class is used to define the utilities required in sso-agent-oidc module.
 */
public class CommonUtils {

    public static final Map<String, TokenData> TOKEN_STORE = new HashMap<>();

    private CommonUtils() {

    }

    public static boolean logout(final HttpServletRequest request, final HttpServletResponse response) {
        // Invalidate session
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        final Optional<Cookie> appIdCookie = getAppIdCookie(request);

        if (appIdCookie.isPresent()) {
            TOKEN_STORE.remove(appIdCookie.get().getValue());
            appIdCookie.get().setMaxAge(0);
            response.addCookie(appIdCookie.get());
            return true;
        }
        return false;
    }

    public static Optional<Cookie> getAppIdCookie(final HttpServletRequest request) {

        final Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("AppID".equals(cookie.getName())) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    public static Optional<TokenData> getTokenDataByCookieID(final String cookieID) {

        if (TOKEN_STORE.containsKey(cookieID)) {
            return Optional.of(TOKEN_STORE.get(cookieID));
        }

        return Optional.empty();
    }
}
