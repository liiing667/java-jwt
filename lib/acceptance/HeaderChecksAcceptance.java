import com.auth0.jwt.HeaderParams;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * End-to-end acceptance check driven by locally signed tokens. Not part of the unit test sources.
 */
public class HeaderChecksAcceptance {

    private static final Algorithm ALGORITHM = Algorithm.HMAC256("shared-secret");
    private static int failures;

    public static void main(String[] args) {
        String standard = JWT.create()
                .withHeader(Collections.singletonMap(HeaderParams.TYPE, "JWT"))
                .withIssuer("auth0")
                .sign(ALGORITHM);

        String accessToken = JWT.create()
                .withHeader(Collections.singletonMap(HeaderParams.TYPE, "at+jwt"))
                .withIssuer("auth0")
                .sign(ALGORITHM);

        Map<String, Object> unknownCritHeader = new HashMap<>();
        unknownCritHeader.put(HeaderParams.TYPE, "JWT");
        unknownCritHeader.put(HeaderParams.CRITICAL, Arrays.asList("https://svc.example/unknown-ext"));
        String unknownCrit = JWT.create().withHeader(unknownCritHeader).withIssuer("auth0").sign(ALGORITHM);

        Map<String, Object> knownCritHeader = new HashMap<>();
        knownCritHeader.put(HeaderParams.TYPE, "JWT");
        knownCritHeader.put("https://svc.example/tenant", "tenant-a");
        knownCritHeader.put(HeaderParams.CRITICAL, Arrays.asList("https://svc.example/tenant"));
        String knownCrit = JWT.create().withHeader(knownCritHeader).withIssuer("auth0").sign(ALGORITHM);

        String noType = manualToken("{\"alg\":\"HS256\"}", "{\"iss\":\"auth0\"}");

        JWTVerifier sharedVerifier = JWT.require(ALGORITHM)
                .withTypes("JWT", "at+jwt")
                .withCriticalExtensions("https://svc.example/tenant")
                .withIssuer("auth0")
                .build();

        expectAccepted(sharedVerifier, standard, "standard JWT typ");
        expectAccepted(sharedVerifier, accessToken, "whitelisted at+jwt typ");
        expectAccepted(sharedVerifier, knownCrit, "registered critical extension present");
        expectRejected(sharedVerifier, unknownCrit, "unknown critical extension");
        expectRejected(sharedVerifier, noType, "missing typ while whitelist configured");

        JWTVerifier defaultVerifier = JWT.require(ALGORITHM).build();
        expectAccepted(defaultVerifier, standard, "default verifier ignores typ");
        expectAccepted(defaultVerifier, noType, "default verifier accepts token without typ");
        expectRejected(defaultVerifier, unknownCrit, "default verifier rejects any crit extension");

        if (failures > 0) {
            System.out.println("ACCEPTANCE FAILED: " + failures + " check(s) failed");
            System.exit(1);
        }
        System.out.println("ACCEPTANCE OK: all header checks behaved as expected");
    }

    private static void expectAccepted(JWTVerifier verifier, String token, String scenario) {
        try {
            DecodedJWT jwt = verifier.verify(token);
            System.out.println("[PASS] accepted: " + scenario + " (typ=" + jwt.getType() + ")");
        } catch (RuntimeException e) {
            failures++;
            System.out.println("[FAIL] expected acceptance for " + scenario + " but got: " + e.getMessage());
        }
    }

    private static void expectRejected(JWTVerifier verifier, String token, String scenario) {
        try {
            verifier.verify(token);
            failures++;
            System.out.println("[FAIL] expected rejection for " + scenario + " but token was accepted");
        } catch (RuntimeException e) {
            System.out.println("[PASS] rejected: " + scenario + " -> " + e.getMessage());
        }
    }

    private static String manualToken(String headerJson, String payloadJson) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ALGORITHM.sign(header.getBytes(StandardCharsets.UTF_8),
                payload.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + encoder.encodeToString(signature);
    }
}
