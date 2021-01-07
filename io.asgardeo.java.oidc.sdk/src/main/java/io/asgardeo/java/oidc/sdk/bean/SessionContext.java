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

package io.asgardeo.java.oidc.sdk.bean;

import java.io.Serializable;

/**
 * A data model class to define the Session Context element. The Session Context object should be used to hold the
 * attributes of the logged in user session. These include the attributes:
 * <ul>
 * <li>The Authenticated User
 * <li>Access Token
 * <li>Refresh Token
 * <li>ID Token
 * </ul>
 * <p>
 */
public class SessionContext implements Serializable {

    private static final long serialVersionUID = 976008884476935474L;

    private User user;
    private String accessToken;
    private String refreshToken;
    private String idToken;

    /**
     * Returns the authenticated user.
     *
     * @return {@link User} object for the authenticated user.
     */
    public User getUser() {

        return user;
    }

    /**
     * Sets the user of the authentication.
     *
     * @param user The user for the authentication.
     */
    public void setUser(User user) {

        this.user = user;
    }

    /**
     * Returns the access token.
     *
     * @return The access token string.
     */
    public String getAccessToken() {

        return accessToken;
    }

    /**
     * Sets the access token.
     *
     * @param accessToken The access token.
     */
    public void setAccessToken(String accessToken) {

        this.accessToken = accessToken;
    }

    /**
     * Returns the refresh token.
     *
     * @return The refresh token string.
     */
    public String getRefreshToken() {

        return refreshToken;
    }

    /**
     * Sets the refresh token.
     *
     * @param refreshToken The refresh token.
     */
    public void setRefreshToken(String refreshToken) {

        this.refreshToken = refreshToken;
    }

    /**
     * Returns the id token.
     *
     * @return The Id token string.
     */
    public String getIdToken() {

        return idToken;
    }

    /**
     * Sets the id token.
     *
     * @param idToken The id token.
     */
    public void setIdToken(String idToken) {

        this.idToken = idToken;
    }
}
