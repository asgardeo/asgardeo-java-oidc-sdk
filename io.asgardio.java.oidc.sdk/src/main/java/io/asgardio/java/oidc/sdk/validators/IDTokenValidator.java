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

package io.asgardio.java.oidc.sdk.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import io.asgardio.java.oidc.sdk.SSOAgentConstants;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * Validator of ID tokens issued by an OpenID Provider.
 *
 * <p>Supports processing of ID tokens with:
 *
 * <ul>
 *     <li>ID tokens signed (JWS) with the OP's RSA or EC key, require the
 *         OP public JWK set (provided by value or URL) to verify them.
 *     <li>ID tokens authenticated with a JWS HMAC, require the client's secret
 *         to verify them.
 * </ul>
 */
public class IDTokenValidator {

    private static final Logger logger = LogManager.getLogger(IDTokenValidator.class);

    private OIDCAgentConfig oidcAgentConfig;
    private JWT idToken;

    public IDTokenValidator(OIDCAgentConfig oidcAgentConfig, JWT idToken) {

        this.oidcAgentConfig = oidcAgentConfig;
        this.idToken = idToken;
    }

    public IDTokenClaimsSet validate(Nonce expectedNonce) throws SSOAgentServerException {

        JWSAlgorithm jwsAlgorithm = validateJWSAlgorithm(oidcAgentConfig, idToken);
        com.nimbusds.openid.connect.sdk.validators.IDTokenValidator validator =
                getIDTokenValidator(oidcAgentConfig, jwsAlgorithm);
        IDTokenClaimsSet claims;
        try {
            claims = validator.validate(idToken, expectedNonce);
            validateAudience(oidcAgentConfig, claims);
        } catch (JOSEException | BadJOSEException e) {
            throw new SSOAgentServerException(e.getMessage(), e.getCause());
        }
        return claims;
    }

    private com.nimbusds.openid.connect.sdk.validators.IDTokenValidator getIDTokenValidator(
            OIDCAgentConfig oidcAgentConfig, JWSAlgorithm jwsAlgorithm) throws SSOAgentServerException {

        Issuer issuer = oidcAgentConfig.getIssuer();
        URI jwkSetURI = oidcAgentConfig.getJwksEndpoint();
        ClientID clientID = oidcAgentConfig.getConsumerKey();
        Secret clientSecret = oidcAgentConfig.getConsumerSecret();
        com.nimbusds.openid.connect.sdk.validators.IDTokenValidator validator;

        // Creates a new validator for RSA, EC or ED protected ID tokens.
        if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm) || JWSAlgorithm.Family.EC.contains(jwsAlgorithm) ||
                JWSAlgorithm.Family.ED.contains(jwsAlgorithm)) {
            try {
                validator =
                        new com.nimbusds.openid.connect.sdk.validators.IDTokenValidator(issuer, clientID, jwsAlgorithm,
                                jwkSetURI.toURL());
            } catch (MalformedURLException e) {
                throw new SSOAgentServerException(e.getMessage(), e.getCause());
            }
            // Creates a new validator for HMAC protected ID tokens.
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlgorithm)) {
            validator = new com.nimbusds.openid.connect.sdk.validators.IDTokenValidator(issuer, clientID, jwsAlgorithm,
                    clientSecret);
        } else {
            throw new SSOAgentServerException(String.format("Unsupported algorithm: %s.", jwsAlgorithm.getName()));
        }
        return validator;
    }

    private JWSAlgorithm validateJWSAlgorithm(OIDCAgentConfig oidcAgentConfig, JWT idToken)
            throws SSOAgentServerException {

        JWSAlgorithm jwsAlgorithm = (JWSAlgorithm) idToken.getHeader().getAlgorithm();
        JWSAlgorithm expectedJWSAlgorithm = oidcAgentConfig.getSignatureAlgorithm();

        if (expectedJWSAlgorithm == null) {
            if (JWSAlgorithm.RS256.equals(jwsAlgorithm)) {
                return jwsAlgorithm;
            } else {
                throw new SSOAgentServerException(String.format("Signed JWT rejected. Provided signature algorithm: " +
                        "%s is not the default of RS256.", jwsAlgorithm.getName()));
            }
        } else if (!expectedJWSAlgorithm.equals(jwsAlgorithm)) {
            throw new SSOAgentServerException(String.format("Signed JWT rejected: Another algorithm expected. " +
                    "Provided signature algorithm: %s.", jwsAlgorithm.getName()));
        }
        return jwsAlgorithm;
    }

    private void validateAudience(OIDCAgentConfig oidcAgentConfig, IDTokenClaimsSet claimsSet)
            throws SSOAgentServerException {

        List<Audience> audience = claimsSet.getAudience();
        if (audience.size() > 1) {
            if (claimsSet.getClaim(SSOAgentConstants.AZP) == null) {
                throw new SSOAgentServerException("ID token validation failed. AZP claim cannot be null for multiple " +
                        "audiences.");
            }
            Set<String> trustedAudience = oidcAgentConfig.getTrustedAudience();
            for (Audience aud : audience) {
                if (!trustedAudience.contains(aud.getValue())) {
                    throw new SSOAgentServerException("ID token validation failed. Untrusted JWT audience.");
                }
            }
        }
    }
}
