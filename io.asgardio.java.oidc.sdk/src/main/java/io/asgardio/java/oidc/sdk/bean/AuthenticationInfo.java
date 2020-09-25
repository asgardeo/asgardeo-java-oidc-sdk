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

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.io.Serializable;

public class AuthenticationInfo implements Serializable {

    private static final long serialVersionUID = 976008884476935474L;

    private User user;
    private AccessToken accessToken;
    private RefreshToken refreshToken;
    private JWT idToken;

    public User getUser() {

        return user;
    }

    public void setUser(User user) {

        this.user = user;
    }

    public AccessToken getAccessToken() {

        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {

        this.accessToken = accessToken;
    }

    public RefreshToken getRefreshToken() {

        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {

        this.refreshToken = refreshToken;
    }

    public JWT getIdToken() {

        return idToken;
    }

    public void setIdToken(JWT idToken) {

        this.idToken = idToken;
    }
}
