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

package io.asgardeo.java.oidc.sdk.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import io.asgardeo.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardeo.java.oidc.sdk.exception.SSOAgentServerException;
import net.jadler.Jadler;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.port;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class IDTokenValidatorTest {

    private OIDCAgentConfig config;
    private RSAKey key;

    @BeforeMethod
    public void setUp() throws Exception {

        initJadler();

        config = new OIDCAgentConfig();
        JWKSet jwkSet = generateJWKS();
        key = (RSAKey) jwkSet.getKeys().get(0);

        Issuer issuer = new Issuer("issuer");
        ClientID clientID = new ClientID("sampleClientId");
        Secret clientSecret = new Secret("sampleClientSecret");
        URL jwkSetURL = new URL("http://localhost:" + port() + "/jwksEP");

        config.setIssuer(issuer);
        config.setConsumerKey(clientID);
        config.setConsumerSecret(clientSecret);
        config.setJwksEndpoint(jwkSetURL.toURI());

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/jwksEP")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(jwkSet.toString(true));
    }

    private JWKSet generateJWKS() throws NoSuchAlgorithmException {

        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        pairGen.initialize(2048);
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

    private com.nimbusds.jose.jwk.ECKey generateECJWK(final Curve curve) throws Exception {

        ECParameterSpec ecParameterSpec = curve.toECParameterSpec();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();

        return new com.nimbusds.jose.jwk.ECKey.Builder(curve, (ECPublicKey) keyPair.getPublic()).
                privateKey((ECPrivateKey) keyPair.getPrivate()).
                build();
    }

    @DataProvider(name = "IssuerData")
    public Object[][] issuerData() {

        Issuer issuer1 = new Issuer("issuer1");
        Issuer issuer2 = new Issuer("issuer2");

        return new Object[][]{
                // issuer
                // expected
                {issuer1, "issuer1"},
                {issuer2, "issuer2"}
        };
    }

    @Test(dataProvider = "IssuerData")
    public void testIssuer(Issuer issuer, String expectedIssuer) throws SSOAgentServerException, JOSEException {

        config.setIssuer(issuer);
        Nonce nonce = new Nonce();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer.getValue())
                .subject("alice")
                .audience(config.getConsumerKey().getValue())
                .expirationTime(new Date())
                .issueTime(new Date())
                .claim("nonce", nonce.getValue())
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        JWSSigner signer = new RSASSASigner(key);
        idToken.sign(signer);

        IDTokenValidator validator = new IDTokenValidator(config, idToken);
        IDTokenClaimsSet claimsSet = validator.validate(nonce);
        assertEquals(claimsSet.getIssuer().getValue(), expectedIssuer);
    }

    @DataProvider(name = "AudienceData")
    public Object[][] audienceData() {

        String clientID1 = "clientID1";
        List<String> tokenAudience1 = Arrays.asList(clientID1);
        Set<String> trustedAudience1 = new HashSet<>(tokenAudience1);
        trustedAudience1.add(clientID1);
        String azp1 = null;

        String clientID2 = "clientID2";
        List<String> tokenAudience2 = Arrays.asList("aud1", "aud2", "aud3", clientID2);
        Set<String> trustedAudience2 = new HashSet<>(tokenAudience2);
        String azp2 = clientID2;

        return new Object[][]{
                // token audience
                // trusted audience
                // client ID
                // AZP value
                {tokenAudience1, trustedAudience1, clientID1, azp1},
                {tokenAudience2, trustedAudience2, clientID2, azp2}
        };
    }

    @Test(dataProvider = "AudienceData")
    public void testAudience(List<String> audience, Set<String> trustedAudience, String clientID, String azpValue)
            throws SSOAgentServerException, JOSEException {

        Nonce nonce = new Nonce();
        config.setTrustedAudience(trustedAudience);
        config.setConsumerKey(new ClientID(clientID));
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(config.getIssuer().getValue())
                .subject("alice")
                .audience(audience)
                .expirationTime(new Date())
                .issueTime(new Date())
                .claim("nonce", nonce.getValue())
                .claim("azp", azpValue)
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        JWSSigner signer = new RSASSASigner(key);
        idToken.sign(signer);

        IDTokenValidator validator = new IDTokenValidator(config, idToken);
        IDTokenClaimsSet claimsSet = validator.validate(nonce);
        List<Audience> audiences = claimsSet.getAudience();
        audiences.forEach(aud -> assertTrue(trustedAudience.contains(aud.getValue())));
    }

    @DataProvider(name = "AlgorithmData")
    public Object[][] algorithmData() throws Exception {

        KeyPairGenerator pairGenRSA = KeyPairGenerator.getInstance("RSA");
        pairGenRSA.initialize(2048);
        KeyPair keyPairRSA = pairGenRSA.generateKeyPair();

        RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey) keyPairRSA.getPublic())
                .privateKey((RSAPrivateKey) keyPairRSA.getPrivate())
                .keyID("1")
                .build();

        ECKey ecJWK = generateECJWK(Curve.P_256);

        return new Object[][]{
                // algorithm
                // key
                {"RS256", (JWK) rsaJWK},
                {"ES256", (JWK) ecJWK}
        };
    }

    @Test(dataProvider = "AlgorithmData")
    public void testJWSAlgorithm(String signatureAlgorithm, JWK key) throws JOSEException, SSOAgentServerException {

        JWKSet jwkSet = new JWKSet(Collections.singletonList(key));

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/jwksEP")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(jwkSet.toString(true));

        Nonce nonce = new Nonce();
        JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(signatureAlgorithm);
        config.setSignatureAlgorithm(jwsAlgorithm);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(config.getIssuer().getValue())
                .subject("alice")
                .audience(config.getConsumerKey().getValue())
                .expirationTime(new Date())
                .issueTime(new Date())
                .claim("nonce", nonce.getValue())
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(jwsAlgorithm), claims);
        JWSSigner signer;
        if (key instanceof RSAKey) {
            signer = new RSASSASigner((RSAKey) key);
        } else {
            signer = new ECDSASigner((ECKey) key);
        }
        idToken.sign(signer);

        IDTokenValidator validator = new IDTokenValidator(config, idToken);
        IDTokenClaimsSet claimsSet = validator.validate(nonce);
        assertEquals(claimsSet.getNonce(), nonce);
    }

    @AfterMethod
    public void tearDown() {

        closeJadler();
    }
}
