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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import io.asgardio.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardio.java.oidc.sdk.exception.SSOAgentServerException;
import net.jadler.Jadler;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;

import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.port;
import static org.testng.Assert.assertEquals;

public class IDTokenValidatorTest {

    OIDCAgentConfig oidcAgentConfig = new OIDCAgentConfig();

    JWKSet jwkSet;

    @BeforeMethod
    public void setUp() throws Exception {

        initJadler();

        try {
            jwkSet = new JWKSet(Collections.singletonList(getJWK()));
        } catch (JOSEException e) {
            //ignored.
        }
        Issuer issuer = new Issuer("issuer");
        ClientID clientID = new ClientID("sampleClientId");
        Secret clientSecret = new Secret("sampleClientSecret");
        URL jwkSetURL = new URL("http://localhost:" + port() + "/jwksEP");

        oidcAgentConfig.setIssuer(issuer);
        oidcAgentConfig.setConsumerKey(clientID);
        oidcAgentConfig.setConsumerSecret(clientSecret);
        oidcAgentConfig.setJwksEndpoint(jwkSetURL.toURI());

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/jwksEP")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(jwkSet.toJSONObject(true).toJSONString());
    }

    private OIDCAgentConfig getConfigForIssuer(String issuer) {

        OIDCAgentConfig config = this.oidcAgentConfig;
        config.setIssuer(new Issuer(issuer));
        return config;
    }

    private JWKSet generateJWKS() throws NoSuchAlgorithmException {

        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        pairGen.initialize(1024);
        KeyPair keyPair = pairGen.generateKeyPair();

        RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("1")
                .build();

        keyPair = pairGen.generateKeyPair();

        RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("2")
                .build();

        JWKSet jwkSet = new JWKSet(Arrays.asList((JWK) rsaJWK1, (JWK) rsaJWK2));
        return jwkSet;
    }

    private JWK getJWK() throws JOSEException {

        String pemEncodedCert = null;
        try {
            pemEncodedCert = IOUtils
                    .readFileToString(new File("src/test/resources/sample-certs/test.crt"), Charset.forName("UTF-8"));
        } catch (IOException e) {
            // Ignored.
        }
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        JWK jwk = JWK.parse(cert);

        return jwk;
    }

    @DataProvider(name = "IssuerData")
    public Object[][] issuerData() {

        return new Object[][]{
                // oidcAgentConfig
                //expected
                {getConfigForIssuer("issuer1"), "issuer1"},
                {getConfigForIssuer("issuer2"), "issuer2"}
        };
    }

    @Test(dataProvider = "IssuerData")
    public void testIssuer(OIDCAgentConfig oidcAgentConfig, String expectedIssuer) throws SSOAgentServerException {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(oidcAgentConfig.getIssuer().getValue())
                .subject("alice")
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);

        IDTokenValidator validator = new IDTokenValidator(oidcAgentConfig, idToken);
        IDTokenClaimsSet claimsSet = validator.validate();
        assertEquals(claimsSet.getIssuer().getValue(), expectedIssuer);
    }

    @AfterMethod
    public void tearDown() {

        closeJadler();
    }
}