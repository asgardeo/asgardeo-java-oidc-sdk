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

import java.io.Serializable;
import java.util.Map;

/**
 * A data model class to define the User element.
 */
public class User implements Serializable {

    private static final long serialVersionUID = -2609465712885072108L;

    private String subject;
    private Map<String, Object> attributes;

    public User(String subject, Map<String, Object> attributes) {

        this.subject = subject;
        this.attributes = attributes;
    }

    /**
     * Returns the subject identifier of the user.
     *
     * @return The subject identifier.
     */
    public String getSubject() {

        return subject;
    }

    /**
     * Returns the attributes of the user.
     *
     * @return {@code Map<String, Object>} of the user attributes.
     */
    public Map<String, Object> getAttributes() {

        return attributes;
    }
}
