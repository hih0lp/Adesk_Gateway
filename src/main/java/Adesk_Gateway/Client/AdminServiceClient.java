package Adesk_Gateway.Client;

import Adesk_Gateway.Models.PermissionCheckRequest;
import Adesk_Gateway.Models.PermissionResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
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
            // Исправь путь - добавь /api/
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

            if (response.getStatusCode() == HttpStatus.OK) {
                log.info("Admin service response: allowed={}, permissions={}",
                        response.getBody().isAllowed(),
                        response.getBody().getPermissions());
                return response.getBody();
            } else {
                log.error("Admin service returned status: {}", response.getStatusCode());
            }

        } catch (Exception e) {
            log.error("Error calling admin service: {}", e.getMessage(), e);
        }

        // По умолчанию запрещаем доступ при ошибке
        return PermissionResponse.builder()
                .allowed(false)
                .reason("Permission check service unavailable")
                .email(request.getEmail())
                .companyId(request.getCompanyId())
                .build();
    }
}