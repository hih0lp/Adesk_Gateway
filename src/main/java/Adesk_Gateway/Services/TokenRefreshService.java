package Adesk_Gateway.Services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenRefreshService {

    private final RestTemplate restTemplate;

    public String refreshCompanyToken(String userEmail, String companyId) {
        try {
            // URL админки для обновления токена
            String url = String.format(
                    "http://localhost:8082/permissions/get-new-token/%s/%s",
                    companyId,
                    userEmail
            );

            log.info("Refreshing token via AdminService. URL: {}", url);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                String newToken = response.getBody();
                log.info("Token refreshed successfully for user: {}, company: {}",
                        userEmail, companyId);
                return newToken;
            }

            log.error("Failed to refresh token. Status: {}, Body: {}",
                    response.getStatusCode(), response.getBody());
            return null;

        } catch (HttpClientErrorException e) {
            log.error("Client error refreshing token: {} - {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (HttpServerErrorException e) {
            log.error("Server error refreshing token: {} - {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage(), e);
            return null;
        }
    }
}