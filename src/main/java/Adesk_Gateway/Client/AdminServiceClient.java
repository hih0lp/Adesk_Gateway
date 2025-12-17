package Adesk_Gateway.Client;

import Adesk_Gateway.Models.PermissionCheckRequest;
import Adesk_Gateway.Models.PermissionResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminServiceClient {

    private final RestTemplate restTemplate;

    @Value("${services.admin.url:http://localhost:8082}")
    private String adminServiceUrl;

    public PermissionResponse checkPermissions(PermissionCheckRequest request) {
        try {
            String url = adminServiceUrl + "/permissions/check";

            log.info("Calling admin service: {}", url);
            log.info("Request: email={}, company={}",
                    request.getEmail(), request.getCompanyId());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<PermissionCheckRequest> entity = new HttpEntity<>(request, headers);

            ResponseEntity<PermissionResponse> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    PermissionResponse.class
            );

            log.info("Admin service response: allowed={}, permissions={}",
                    response.getBody().isAllowed(),
                    response.getBody().getPermissions());
            return response.getBody();

        } catch (HttpClientErrorException e) {
            // Admin Service вернул 4xx ошибку (400, 401, 403, 404)
            log.warn("Admin service returned {}: {}", e.getStatusCode(), e.getMessage());
            // Пробрасываем дальше - обработается в GatewayController
            throw e;

        } catch (HttpServerErrorException e) {
            // Admin Service вернул 5xx ошибку (500, 502, 503)
            log.error("Admin service error {}: {}", e.getStatusCode(), e.getMessage());
            throw e;

        } catch (Exception e) {
            // Ошибки сети, таймауты и т.д.
            log.error("Error calling admin service: {}", e.getMessage(), e);
            throw new RuntimeException("Permission service unavailable: " + e.getMessage());
        }
    }
}