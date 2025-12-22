package Adesk_Gateway.Controllers;

import Adesk_Gateway.Models.PermissionCheckRequest;
import Adesk_Gateway.Models.PermissionResponse;
import Adesk_Gateway.Services.TokenRefreshService;
import Adesk_Gateway.Services.TokenService;
import Adesk_Gateway.Client.AdminServiceClient;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import jakarta.servlet.http.HttpServlet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/gateway")
@RequiredArgsConstructor
//@CircuitBreaker(name = "Gateway", fallbackMethod = "globalFallback")
public class GatewayController {

    private final RestTemplate restTemplate;
    private final TokenService tokenService;
    private final AdminServiceClient adminServiceClient;
    private final TokenRefreshService tokenRefreshService;

    // ==================== CHECKS SERVICE ====================
    @PostMapping("/checks/create-category") //протестил
    public ResponseEntity<?> createCheckCategoryAsync(@RequestBody Object body,
                                         HttpServletRequest request) {
        return forwardWithPermissionCheck(
//                "checks",
                "http://localhost:8082/checks/create-category",
                request,
                body
        );
    }

    @DeleteMapping("/checks/delete-category") //протестил
    public ResponseEntity<?> deleteCheckCategoryAsync(@RequestBody Object body,
                                                      HttpServletRequest request) {
        return forwardWithPermissionCheck(
//                "checks",
                "http://localhost:8082/checks/delete-category",
                request,
                body
        );
    }


    @PostMapping("/checks/create-check") //протестил
    public ResponseEntity<?> createCheckAsync(@RequestBody Object body,
                                         HttpServletRequest request) {
        return forwardWithPermissionCheck(
//                "checks",
                "http://localhost:8082/checks/create-check",
                request,
                body
        );
    }


    @GetMapping("/checks/get-categories-by-company-id/{companyId}") //протестил
    public ResponseEntity<?> getCheckCategoriesByCompanyIdAsync(@PathVariable String companyId,
                                         HttpServletRequest request) {
        return forwardWithPermissionCheck(
//                "checks",
                "http://localhost:8082/checks/get-categories-by-company-id/" + companyId,
                request,
                null
        );
    }

    @GetMapping("/checks/get-checks-by-company-id/{companyId}") //протестил
    public ResponseEntity<?> getChecksByCompanyIdAsync(@PathVariable String companyId,
                                                                HttpServletRequest request) {
        return forwardWithPermissionCheck(
//                "checks",
                "http://localhost:8082/checks/get-checks-by-company-id/" + companyId,
                request,
                null
        );
    }


    // ==================== COMPANY SERVICE ====================

    @PostMapping("/company/invite-member") //протестил
    public ResponseEntity<?> inviteMemberAsync(@RequestBody Object body,
                                          HttpServletRequest request) {
        return forwardWithPermissionCheck(
//                "admin",
                "http://localhost:8082/company/invite-member",
                request,
                body
        );
    }

    @GetMapping("/company/accept-invite/{token}") //протестил
    public ResponseEntity<?> acceptInviteAsync(@PathVariable String token,
                                          HttpServletRequest request) {
        // Публичный эндпоинт - не проверяем права
        return forwardRequest(
                "http://localhost:8082/company/accept-invite/" + token,
                request,
                null,
                null,
                false  // Без токена
        );
    }

    @PutMapping("/company/edit-company-name") //протестил
    public ResponseEntity<?> editCompanyNameAsync(@RequestBody Object body,
                                                  HttpServletRequest request){

        return forwardWithPermissionCheck(
//                "admin",
                "http://localhost:8082/company/edit-company-name",
                request,
                body);
    }

    @GetMapping("/company/get-user-companies-by-email/{userEmail}") //протестил
    public ResponseEntity<?> getCompaniesByUserEmailAsync(@PathVariable String userEmail,
                                                          HttpServletRequest request){
        return forwardRequest(
                "http://localhost:8082/company/get-user-companies-by-email/" + userEmail,
                request,
                null,
                null,
                false
        );
    }

    @PutMapping("/company/edit-user-rights") //протестил
    public ResponseEntity<?> editUserRightsAsync(@RequestBody Object body,
                                                 HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8082/company/edit-user-rights",
                request,
                body
        );
    }

    @DeleteMapping("/company/delete-user-from-company/{companyId}/{userEmail}") //
    public ResponseEntity<?> deleteUserFromCompanyAsync(@PathVariable String companyId,
                                                   @PathVariable String userEmail,
                                                   HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8082/company/delete-user-from-company/" + companyId + "/" + userEmail,
                request,
                null
        );
    }

    @GetMapping("/company/is-company-exist/{companyId}") //протестил
    public ResponseEntity<?> isCompanyExistAsync(@PathVariable String companyId, HttpServletRequest request){
        return forwardRequest(
                "http://localhost:8082/company/is-company-exist/" + companyId,
                request,
                null,
                null,
                false
        );
    }

    @PostMapping("/company/create-company/{userEmail}") //протестил
    public ResponseEntity<?> createCompanyAsync(@PathVariable String userEmail, @RequestBody Object body, HttpServletRequest request){
        return forwardRequest(
                "http://localhost:8082/company/create-company/" + userEmail,
                request,
                body,
                null,
                false
        );
    }

    //===================== PROJECT SERVICE ===========================
    @PostMapping("/projects/create-category") //протестил
    public ResponseEntity<?> createProjectCategoryAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8084/projects/create-category",
                request,
                body
        );
    }

    @DeleteMapping("/projects/delete-category") //протестил
    public ResponseEntity<?> deleteCategoryAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8084/projects/delete-category",
                request,
                body
        );
    }

    @PostMapping("/projects/create-project") //протестил
    public ResponseEntity<?> createProjectAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8084/projects/create-project",
                request,
                body
        );
    }


    @DeleteMapping("/projects/delete-project") //протестил
    public ResponseEntity<?> deleteProjectAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8084/projects/delete-project" ,
                request,
                body
        );
    }

    // ==================== OPERATION SERVICE ==========================

    @PostMapping("/operations/create-operation")
    public ResponseEntity<?> createOperationAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/operations/create-operation",
                request,
                body
        );
    }

    @DeleteMapping("/operations/delete-operations")
    public ResponseEntity<?> deleteOperationsAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/operations/delete-operation",
                request,
                body
        );
    }


    // ==================== IDENTITY SERVICE ==========================

    @PostMapping("/auth/registrate-user") //протестил
    public ResponseEntity<?> registrateUserAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardRequest(
          "http://localhost:8080/auth/registrate-user",
                request,
                body,
                null,
                false
        );
    }

    @PostMapping("/auth/login") //протестил
    public ResponseEntity<?> logInAndSendAuthCodeAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardRequest(
            "http://localhost:8080/auth/login",
                request,
                body,
                null,
                false
        );
    }

    @PostMapping("/auth/verify-code") //протестил
    public ResponseEntity<?> verifyUserAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardRequest(
                "http://localhost:8080/auth/verify-code",
                request,
                body,
                null,
                false
        );
    }

    /// TODO : СДЕЛАТЬ ЗАПРОС, КОТОРЫЙ БУДЕТ ОБНОВЛЯТЬ ТОКЕН ПОСЛЕ ИСТЕЧЕНИЯ ЕГО СРОКА ГОДНОСТИ

    // ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================


    private ResponseEntity<?> forwardWithPermissionCheck(String targetUrl,
                                                         HttpServletRequest request,
                                                         Object body) {
        try {
            String token = extractToken(request);
            if (token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Missing authorization token".getBytes());
            }

            // 1. Проверяем, истек ли токен
            boolean isTokenExpired = tokenService.isTokenExpired(token);

            // 2. Извлекаем данные (даже из истекшего токена)
            String email = tokenService.extractUserEmail(token);
            String companyId = tokenService.extractCompanyId(token);

            if (email == null || companyId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid token data".getBytes());
            }

            // 3. Если токен истек - пытаемся обновить
            String newToken = null;
            if (isTokenExpired) {
                log.info("Token expired for user: {}, company: {}. Attempting refresh...",
                        email, companyId);

                newToken = tokenRefreshService.refreshCompanyToken(email, companyId);

                if (newToken != null) {
                    log.info("Token refreshed successfully. New token will be used for permission check");
                    // Используем новый токен для проверки прав
                    token = newToken;
                } else {
                    log.warn("Failed to refresh token. Returning 401 with refresh hint");
                    // Возвращаем 401 с указанием, что нужно обновить токен
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .header("X-Token-Expired", "true")
                            .header("X-Token-Refresh-Required", "true")
                            .header("X-Refresh-Endpoint", "/api/gateway/refresh-token")
                            .body("Token expired. Please refresh your token.".getBytes());
                }
            }

            // 4. Проверяем права с актуальным токеном (новым или старым)
            PermissionCheckRequest permissionRequest = PermissionCheckRequest.builder()
                    .email(email)
                    .companyId(companyId)
                    .path(request.getRequestURI())
                    .method(request.getMethod())
                    .requestParams(extractRequestParams(request))
                    .build();

            PermissionResponse permissionResponse = adminServiceClient
                    .checkPermissions(permissionRequest);

            if (!permissionResponse.isAllowed()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(("Access denied: " + permissionResponse.getReason()).getBytes());
            }

            // 5. Проксируем запрос
            ResponseEntity<?> forwardedResponse = forwardRequest(targetUrl, request, body, permissionResponse, true);

            // 6. Если был обновлен токен, добавляем его в заголовки ответа
            if (newToken != null && forwardedResponse.getStatusCode().is2xxSuccessful()) {
                HttpHeaders newHeaders = new HttpHeaders();
                forwardedResponse.getHeaders().forEach(newHeaders::addAll);
                newHeaders.add("X-New-Access-Token", newToken); //новый токен аксес
                newHeaders.add("X-Token-Refreshed", "true"); //пометка, что токен рефрешнут был

                return ResponseEntity.status(forwardedResponse.getStatusCode())
                        .headers(newHeaders)
                        .body(forwardedResponse.getBody());
            }

            return forwardedResponse;

        } catch (HttpClientErrorException e) {
            return ResponseEntity
                    .status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsByteArray());

        } catch (HttpServerErrorException e) {
            return ResponseEntity
                    .status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsByteArray());

        } catch (Exception e) {
            log.error("Gateway error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Gateway error: " + e.getMessage()).getBytes());
        }
    }


    // ==================== TOKEN REFRESH ENDPOINT ====================

    @PostMapping("/refresh-token") //это просто рефреш
    public ResponseEntity<?> refreshTokenEndpoint(@RequestHeader(value = "Authorization", required = false) String authHeader,
                                                  @RequestParam(value = "companyId", required = false) String companyIdParam) {
        try {
            String token = null;
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }

            String email = null;
            String companyId = companyIdParam;

            // Если есть токен - извлекаем данные из него
            if (token != null) {
                email = tokenService.extractUserEmail(token);
                if (companyId == null) {
                    companyId = tokenService.extractCompanyId(token);
                }
            }

            // Если не удалось получить email и companyId
            if (email == null || companyId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Cannot determine user and company. Please provide Authorization header or email and companyId parameters.".getBytes());
            }

            log.info("Explicit token refresh requested for user: {}, company: {}", email, companyId);

            String newToken = tokenRefreshService.refreshCompanyToken(email, companyId);

            if (newToken != null) {
                return ResponseEntity.ok()
                        .header("Authorization", "Bearer " + newToken)
                        .header("X-Token-Refreshed", "true")
                        .body(("Token refreshed successfully for company: " + companyId).getBytes());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Failed to refresh token. Please login again.".getBytes());
            }

        } catch (Exception e) {
            log.error("Error in refresh-token endpoint: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error refreshing token: " + e.getMessage()).getBytes());
        }
    }


    @PostMapping("/refresh-token/with-body") // рефреш с телом запроса
    public ResponseEntity<?> refreshTokenWithBody(@RequestBody(required = false) Map<String, String> requestBody) {
        try {
            String email = requestBody != null ? requestBody.get("email") : null;
            String companyId = requestBody != null ? requestBody.get("companyId") : null;
            String token = requestBody != null ? requestBody.get("token") : null;

            // Если передан токен - извлекаем данные из него
            if (token != null && (email == null || companyId == null)) {
                email = tokenService.extractUserEmail(token);
                companyId = tokenService.extractCompanyId(token);
            }

            if (email == null || companyId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Required parameters: email and companyId, or a valid token".getBytes());
            }

            log.info("Token refresh via body for user: {}, company: {}", email, companyId);

            String newToken = tokenRefreshService.refreshCompanyToken(email, companyId);

            if (newToken != null) {
                Map<String, String> response = new HashMap<>();
                response.put("access_token", newToken);
                response.put("token_type", "Bearer");
                response.put("message", "Token refreshed successfully");

                return ResponseEntity.ok()
                        .header("Authorization", "Bearer " + newToken)
                        .body(response.toString().getBytes());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Failed to refresh token".getBytes());
            }

        } catch (Exception e) {
            log.error("Error in refresh-token with body: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error: " + e.getMessage()).getBytes());
        }
    }

    //без проверки токена - если методы не в компании или еще чето
    private ResponseEntity<?> forwardWithoutToken(String targetUrl,
                                                  HttpServletRequest request,
                                                  Object body) {
        try {
            return forwardRequest(targetUrl, request, body, null, false);

        } catch (HttpClientErrorException | HttpServerErrorException e) {
            // Пробрасываем HTTP ошибки от сервиса
            throw e;

        } catch (Exception e) {
            log.error("Gateway error without token check: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Gateway error: " + e.getMessage());
        }
    }

    private ResponseEntity<?> forwardRequest(String targetUrl,
                                             HttpServletRequest request,
                                             Object body,
                                             PermissionResponse permissionResponse,
                                             boolean withToken) {
        try {
            HttpHeaders headers = buildHeaders(request, permissionResponse, withToken);
            HttpMethod method = HttpMethod.valueOf(request.getMethod());
            HttpEntity<Object> entity = new HttpEntity<>(body, headers);

            ResponseEntity<byte[]> response = restTemplate.exchange(
                    targetUrl,
                    method,
                    entity,
                    byte[].class
            );

            return ResponseEntity
                    .status(response.getStatusCode())
                    .headers(cleanHeaders(response.getHeaders()))
                    .body(response.getBody());

        } catch (HttpClientErrorException e) {
            // 4xx ошибки от целевого сервиса
            log.warn("Target service returned {}: {}", e.getStatusCode(), e.getStatusText());
            return ResponseEntity
                    .status(e.getStatusCode())           // ← Оригинальный статус
                    .headers(e.getResponseHeaders())     // ← Оригинальные заголовки
                    .body(e.getResponseBodyAsByteArray()); // ← Оригинальное тело

        } catch (HttpServerErrorException e) {
            // 5xx ошибки от целевого сервиса
            log.error("Target service error {}: {}", e.getStatusCode(), e.getStatusText());
            return ResponseEntity
                    .status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsByteArray());

        } catch (Exception e) {
            // Ошибки Gateway (сеть, таймауты и т.д.)
            log.error("Gateway forwarding error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("Gateway error: Service unavailable".getBytes());
        }
    }

    private HttpHeaders buildHeaders(HttpServletRequest request,
                                     PermissionResponse permissionResponse,
                                     boolean withToken) {
        HttpHeaders headers = new HttpHeaders();

        // Копируем оригинальные заголовки
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!shouldSkipHeader(headerName)) {
                headers.add(headerName, request.getHeader(headerName));
            }
        }

        // Если запрос с токеном и есть permissionResponse, добавляем права пользователя
        if (withToken && permissionResponse != null) {
            headers.add("X-User-Email", permissionResponse.getEmail());
            headers.add("X-Company-Id", permissionResponse.getCompanyId());

            if (permissionResponse.getPermissions() != null) {
                headers.add("X-User-Permissions",
                        String.join(",", permissionResponse.getPermissions()));
            }

            headers.add("X-Authenticated", "true");
        } else {
            headers.add("X-Authenticated", "false");
        }

        return headers;
    }

    //достаю параметры запросы
    private Map<String, String> extractRequestParams(HttpServletRequest request) {
        Map<String, String> params = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (values.length > 0) {
                params.put(key, values[0]);
            }
        });
        return params;
    }

    private HttpHeaders cleanHeaders(HttpHeaders originalHeaders) {
        HttpHeaders cleaned = new HttpHeaders();
        originalHeaders.forEach((key, values) -> {
            // Убираем внутренние заголовки
            if (!key.toLowerCase().startsWith("x-")) {
                cleaned.addAll(key, values);
            }
        });
        return cleaned;
    }

    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private boolean shouldSkipHeader(String headerName) {
        return headerName.equalsIgnoreCase("host") ||
                headerName.equalsIgnoreCase("content-length");
    }
}



///"X-User-Email" - имейл юзера, если есть, только с токенами
/// "X-Company-Id" - айди компании
/// "X-User-Permissions" - права пользователя через запятую, только те права, которые есть
/// "X-Authenticated" - публичный ли эндпоинт, точнее, вернулся ли он через гейтвей


/// TODO - АВТОМАТИЧЕСКОЕ ОБНОВЛЕНИЕ ТОКЕНА (ВЫКИДЫВАЕТСЯ В ЗАГОЛОВКАХ)