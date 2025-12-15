package Adesk_Gateway.Interfaces;

import java.util.Optional;

public interface ITokenService {
    Optional<String> generateTokenAsync(String userEmail, String companyId);
    String extractUserEmail(String token);
    String extractCompanyId(String token);
    boolean isTokenValid(String token);
}