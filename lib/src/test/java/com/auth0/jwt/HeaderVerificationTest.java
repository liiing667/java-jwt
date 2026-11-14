package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;

/**
 * Verifies the configurable "typ" whitelist and the RFC 7515 "crit" header checks on a shared verifier.
 */
public class HeaderVerificationTest {

    private static final String SECRET = "secret";
    private static Algorithm algorithm;

    private static String jwtToken;
    private static String atJwtToken;
    private static String noTypeToken;
    private static String unknownCriticalExtensionToken;
    private static String knownCriticalExtensionToken;
    private static String criticalExtensionWithoutHeaderToken;
    private static String emptyCriticalToken;
    private static String nonArrayCriticalToken;
    private static String duplicateCriticalToken;
    private static String blankCriticalEntryToken;

    /**
     * Signs all token fixtures locally with the library's own HMAC algorithm.
     */
    @BeforeClass
    public static void createFixtures() {
        algorithm = Algorithm.HMAC256(SECRET);

        jwtToken = signedToken(Collections.singletonMap(HeaderParams.TYPE, "JWT"), null);
        atJwtToken = signedToken(Collections.singletonMap(HeaderParams.TYPE, "at+jwt"), null);
        noTypeToken = manuallySignedToken("{\"alg\":\"HS256\"}", "{\"iss\":\"auth0\"}");

        unknownCriticalExtensionToken = signedToken(headerWithCrit(
                Collections.singletonMap(HeaderParams.TYPE, "JWT"),
                Arrays.asList("http://example.com/Unknown"), null), null);

        Map<String, Object> knownExtensionHeader = new HashMap<>();
        knownExtensionHeader.put(HeaderParams.TYPE, "JWT");
        knownExtensionHeader.put("http://example.com/Known", "processed-value");
        knownCriticalExtensionToken = signedToken(headerWithCrit(
                knownExtensionHeader, Arrays.asList("http://example.com/Known"), null), null);

        criticalExtensionWithoutHeaderToken = signedToken(headerWithCrit(
                Collections.singletonMap(HeaderParams.TYPE, "JWT"),
                Arrays.asList("http://example.com/Missing"), null), null);

        emptyCriticalToken = signedToken(headerWithCrit(
                Collections.singletonMap(HeaderParams.TYPE, "JWT"),
                Collections.<String>emptyList(), null), null);

        nonArrayCriticalToken = signedToken(headerWithCrit(
                Collections.singletonMap(HeaderParams.TYPE, "JWT"), null, "not-a-list"), null);

        duplicateCriticalToken = signedToken(headerWithCrit(
                withExtensionHeader(Arrays.asList("http://example.com/Known", "http://example.com/Known")),
                Arrays.asList("http://example.com/Known", "http://example.com/Known"), null), null);

        blankCriticalEntryToken = signedToken(headerWithCrit(
                Collections.singletonMap(HeaderParams.TYPE, "JWT"),
                Arrays.asList("  "), null), null);
    }

    private static String signedToken(Map<String, Object> header, Map<String, Object> payload) {
        return JWT.create()
                .withHeader(header)
                .withIssuer("auth0")
                .sign(algorithm);
    }

    private static String manuallySignedToken(String headerJson, String payloadJson) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signature;
        try {
            signature = algorithm.sign(header.getBytes(StandardCharsets.UTF_8),
                    payload.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return header + "." + payload + "." + encoder.encodeToString(signature);
    }

    private static Map<String, Object> headerWithCrit(
            Map<String, Object> header, java.util.List<String> critList, String critValue) {
        Map<String, Object> headerClaims = new LinkedHashMap<>(header);
        if (critList != null) {
            headerClaims.put(HeaderParams.CRITICAL, critList);
        } else if (critValue != null) {
            headerClaims.put(HeaderParams.CRITICAL, critValue);
        }
        return headerClaims;
    }

    private static Map<String, Object> withExtensionHeader(java.util.List<String> critList) {
        Map<String, Object> header = new HashMap<>();
        header.put(HeaderParams.TYPE, "JWT");
        header.put("http://example.com/Known", "processed-value");
        header.put(HeaderParams.CRITICAL, critList);
        return header;
    }

    @Test
    public void shouldAcceptTokenWhenTypeIsInWhitelist() {
        DecodedJWT jwt = JWT.require(algorithm)
                .withTypes("JWT", "at+jwt")
                .build()
                .verify(jwtToken);
        assertThat(jwt, is(notNullValue()));

        DecodedJWT atJwt = JWT.require(algorithm)
                .withType("at+jwt")
                .build()
                .verify(atJwtToken);
        assertThat(atJwt, is(notNullValue()));
    }

    @Test
    public void shouldRejectTokenWhenTypeIsNotInWhitelist() {
        JWTVerificationException e = assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withTypes("at+jwt")
                        .build()
                        .verify(jwtToken));
        assertThat(e.getMessage(), containsString("typ"));
    }

    @Test
    public void shouldRejectTokenWithoutTypeWhenWhitelistIsConfigured() {
        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withType("JWT")
                        .build()
                        .verify(noTypeToken));
    }

    @Test
    public void shouldNotValidateTypeWhenWhitelistIsNotConfigured() {
        DecodedJWT jwt = JWT.require(algorithm)
                .withIssuer("auth0")
                .build()
                .verify(atJwtToken);
        assertThat(jwt, is(notNullValue()));

        DecodedJWT noType = JWT.require(algorithm)
                .build()
                .verify(noTypeToken);
        assertThat(noType, is(notNullValue()));
    }

    @Test
    public void shouldReplacePreviousTypeWhitelist() {
        DecodedJWT jwt = JWT.require(algorithm)
                .withTypes("at+jwt")
                .withTypes("JWT")
                .build()
                .verify(jwtToken);
        assertThat(jwt, is(notNullValue()));

        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withTypes("at+jwt")
                        .withTypes("JWT")
                        .build()
                        .verify(atJwtToken));
    }

    @Test
    public void shouldThrowWhenTypeWhitelistIsInvalid() {
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withTypes((String[]) null));
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withTypes());
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withTypes("JWT", null));
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withTypes("JWT", "  "));
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withType(""));
    }

    @Test
    public void shouldRejectUnknownCriticalExtensionByDefault() {
        JWTVerificationException e = assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .build()
                        .verify(unknownCriticalExtensionToken));
        assertThat(e.getMessage(), containsString("http://example.com/Unknown"));
    }

    @Test
    public void shouldRejectUnknownCriticalExtensionEvenWhenAnotherOneIsRegistered() {
        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withCriticalExtensions("http://example.com/Other")
                        .build()
                        .verify(unknownCriticalExtensionToken));
    }

    @Test
    public void shouldAcceptKnownAndPresentCriticalExtension() {
        DecodedJWT jwt = JWT.require(algorithm)
                .withCriticalExtensions("http://example.com/Known")
                .build()
                .verify(knownCriticalExtensionToken);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldRejectCriticalExtensionWhenHeaderParameterIsMissing() {
        JWTVerificationException e = assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withCriticalExtensions("http://example.com/Missing")
                        .build()
                        .verify(criticalExtensionWithoutHeaderToken));
        assertThat(e.getMessage(), containsString("not present"));
    }

    @Test
    public void shouldRejectEmptyCriticalHeader() {
        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withCriticalExtensions("http://example.com/Known")
                        .build()
                        .verify(emptyCriticalToken));
    }

    @Test
    public void shouldRejectNonArrayCriticalHeader() {
        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withCriticalExtensions("not-a-list")
                        .build()
                        .verify(nonArrayCriticalToken));
    }

    @Test
    public void shouldRejectDuplicateCriticalHeaderEntries() {
        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .withCriticalExtensions("http://example.com/Known")
                        .build()
                        .verify(duplicateCriticalToken));
    }

    @Test
    public void shouldRejectBlankCriticalHeaderEntry() {
        assertThrows(JWTVerificationException.class, () ->
                JWT.require(algorithm)
                        .build()
                        .verify(blankCriticalEntryToken));
    }

    @Test
    public void shouldAcceptTokenWithoutCriticalHeader() {
        DecodedJWT jwt = JWT.require(algorithm)
                .withCriticalExtensions("http://example.com/Known")
                .withIssuer("auth0")
                .build()
                .verify(jwtToken);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldCombineTypeWhitelistCriticalAndClaimsChecksOnSharedVerifier() {
        com.auth0.jwt.interfaces.JWTVerifier verifier = JWT.require(algorithm)
                .withType("JWT")
                .withCriticalExtensions("http://example.com/Known")
                .withIssuer("auth0")
                .build();

        assertThat(verifier.verify(knownCriticalExtensionToken), is(notNullValue()));

        assertThrows(JWTVerificationException.class, () -> verifier.verify(unknownCriticalExtensionToken));
        assertThrows(JWTVerificationException.class, () -> verifier.verify(atJwtToken));
        assertThrows(JWTVerificationException.class, () -> verifier.verify(jwtTokenWithIssuer("evil")));
    }

    @Test
    public void shouldThrowWhenCriticalExtensionNamesAreInvalid() {
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withCriticalExtensions((String[]) null));
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withCriticalExtensions());
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withCriticalExtensions("valid", null));
        assertThrows(IllegalArgumentException.class, () ->
                JWT.require(algorithm).withCriticalExtensions("   "));
    }

    private String jwtTokenWithIssuer(String issuer) {
        return JWT.create()
                .withHeader(Collections.singletonMap(HeaderParams.TYPE, "JWT"))
                .withIssuer(issuer)
                .sign(algorithm);
    }
}
