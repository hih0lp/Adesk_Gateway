package Adesk_Gateway.Services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

@Service
@Slf4j
public class TokenService {

    private String secret = "v98Td7wS3j5uFU";

    public String extractUserEmail(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String email = claims.get("email", String.class);
            log.info("Extracted email: {}", email);
            return email;
        } catch (Exception e) {
            log.error("Error extracting email from token: {}", e.getMessage());
            return null;
        }
    }

    public String extractCompanyId(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String companyId = claims.get("company", String.class);
            log.info("Extracted companyId: {}", companyId);
            return companyId;
        } catch (Exception e) {
            log.error("Error extracting companyId from token: {}", e.getMessage());
            return null;
        }
    }

    private Claims extractAllClaims(String token) {
        try {
            log.info("Parsing token with secret: {}", secret);

            return Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.error("Error parsing token: {}", e.getMessage(), e);
            throw new RuntimeException("Invalid token: " + e.getMessage());
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] paddedKey = new byte[64];
        System.arraycopy(keyBytes, 0, paddedKey, 0, Math.min(keyBytes.length, paddedKey.length));
        return Keys.hmacShaKeyFor(paddedKey);
    }
}