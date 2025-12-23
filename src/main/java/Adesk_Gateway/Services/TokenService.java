package Adesk_Gateway.Services;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
@Slf4j
public class TokenService {

    private String secret = "v98Td7wS3j5uFU";

    public String extractUserEmail(String token) {
        try {
            Claims claims = extractAllClaimsIgnoringExpiration(token);
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
            Claims claims = extractAllClaimsIgnoringExpiration(token);
            String companyId = claims.get("company", String.class);
            log.info("Extracted companyId: {}", companyId);
            return companyId;
        } catch (Exception e) {
            log.error("Error extracting companyId from token: {}", e.getMessage());
            return null;
        }
    }

    // Проверяет, истек ли токен
    public boolean isTokenExpired(String token) {
        try {
            // Пробуем распарсить с проверкой expiration
            extractAllClaimsWithExpirationCheck(token);
            return false; // Не истек
        } catch (ExpiredJwtException e) {
            log.info("Token is expired: {}", e.getMessage());
            return true; // Истек
        } catch (Exception e) {
            log.error("Error checking token expiration: {}", e.getMessage());
            return true; // Другие ошибки считаем как истекший
        }
    }

    // Извлекает claims даже из истекшего токена - РАБОЧАЯ ВЕРСИЯ!
    private Claims extractAllClaimsIgnoringExpiration(String token) {
        try {
            log.info("Parsing token (ignoring expiration)");

            // ВАРИАНТ 1: Самый надежный - ручной парсинг Base64
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid JWT structure");
            }

            // Декодируем payload (вторая часть)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

//            // Парсим JSON вручную или через Jackson
//            return Jwts.parser()
//                    .json(new JacksonDeserializer<>())
//                    .build()
//                    .parseClaimsJson(payload);

//             ВАРИАНТ 2: Через JWT парсер с отключенной валидацией
             return Jwts.parser()
                     .verifyWith(getSigningKey())
                     .unsecured()  // Отключаем ВСЕ проверки
                     .build()
                     .parseSignedClaims(token)
                     .getPayload();

        } catch (ExpiredJwtException e) {
            // Даже если вылетело ExpiredJwtException - берем claims из исключения!
            log.warn("Token expired, but extracting claims from exception");
            return e.getClaims();
        } catch (Exception e) {
            log.error("Error parsing token: {}", e.getMessage(), e);
            throw new RuntimeException("Invalid token: " + e.getMessage());
        }
    }

    // Извлекает с проверкой expiration (для определения истек ли токен)
    private Claims extractAllClaimsWithExpirationCheck(String token) {
        try {
            log.info("Parsing token with expiration check");

            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch (ExpiredJwtException e) {
            log.info("Token expired: {}", e.getMessage());
            throw e; // Пробрасываем дальше
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