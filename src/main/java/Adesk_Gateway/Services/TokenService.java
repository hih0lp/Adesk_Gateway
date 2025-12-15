package Adesk_Gateway.Services;

import Adesk_Gateway.Interfaces.ITokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Slf4j
@Service
public class TokenService implements ITokenService {

    private final String secret = "v98Td7wS3j5uFU";
    private final SecretKey secretKey;

    public TokenService() {
        // Инициализируем ключ один раз
        this.secretKey = getSigningKey();
    }

    @Override
    public Optional<String> generateTokenAsync(String userEmail, String companyId) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("email", userEmail);
            claims.put("company", companyId);

            return Optional.of(createToken(claims, userEmail));
        } catch (Exception ex) {
            log.error("Error generating token: {}", ex.getMessage(), ex);
            return Optional.empty();
        }
    }

    public String extractUserEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }

    public String extractCompanyId(String token) {
        return extractClaim(token, claims -> claims.get("company", String.class));
    }

    public boolean isTokenValid(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception ex) {
            log.error("Token validation error: {}", ex.getMessage());
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception ex) {
            log.error("Error parsing token: {}", ex.getMessage());
            throw new RuntimeException("Invalid token", ex);
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        // Для HS512 нужен ключ минимум 512 бит (64 байта)
        if (keyBytes.length < 64) {
            byte[] paddedKey = new byte[64];
            System.arraycopy(keyBytes, 0, paddedKey, 0, Math.min(keyBytes.length, paddedKey.length));
            return Keys.hmacShaKeyFor(paddedKey);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 2 * 24 * 60 * 60 * 1000L))
                .signWith(secretKey, io.jsonwebtoken.SignatureAlgorithm.HS512)
                .compact();
    }
}