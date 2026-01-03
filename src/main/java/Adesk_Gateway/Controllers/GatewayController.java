package Adesk_Gateway.Controllers;

import Adesk_Gateway.Models.PermissionCheckRequest;
import Adesk_Gateway.Models.PermissionResponse;
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

    @GetMapping("/projects/get-company-projects")
    public ResponseEntity<?> getCompanyProjects(HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8084/projects/get-company-projects",
                request,
                null
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

    @PostMapping("/requests/create-request")
    public ResponseEntity<?> createOperationAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/create-request",
                request,
                body
        );
    }

    @DeleteMapping("/requests/delete-requests")
    public ResponseEntity<?> deleteOperationsAsync(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/delete-requests",
                request,
                body
        );
    }

    @GetMapping("/requests/get-requests")
    public ResponseEntity<?> getRequestsByProjectNameAsync(HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/get-requests",
                request,
                null
        );
    }

    @PostMapping("/requests/approve-request/{requestId}")
    public ResponseEntity<?> approveRequestAsync(@PathVariable String requestId, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/approve-request/" + requestId,
                request,
                null
        );
    }


    @PostMapping("/requests/disapprove-request/{requestId}")
    public ResponseEntity<?> disapproveRequestAsync(@PathVariable String requestId, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/disapprove-request/" + requestId,
                request,
                null
        );
    }


    @GetMapping("/requests/get-requests-order-by-date-today")
    public ResponseEntity<?> getRequestsOrderByDateToday(HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/get-requests-order-by-date-today",
                request,
                null
        );
    }

    @GetMapping("/requests/get-requests-order-by-date-week")
    public ResponseEntity<?> getRequestsOrderByDateWeek(HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/get-requests-order-by-date-week",
                request,
                null
        );
    }

    @PostMapping("/requests/get-requests-order-by-dates")
    public ResponseEntity<?> getRequestsOrderByDates(@RequestBody Object body, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/get-requests-order-by-dates",
                request,
                body
        );
    }

    @GetMapping("/requests/get-requests-order-by-date-quarter/{numberOfQuarter}")
    public ResponseEntity<?> getRequestsOrderByQuarter(@PathVariable String numberOfQuarter, HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/get-requests-order-by-date-quarter/" + numberOfQuarter,
                request,
                null
        );
    }

    @GetMapping("/requests/get-requests-order-by-date-year")
    public ResponseEntity<?> getRequestsOrderByYear(HttpServletRequest request){
        return forwardWithPermissionCheck(
                "http://localhost:8087/requests/get-requests-order-by-date-year",
                request,
                null
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
    // ===================






    // ==================== REFRESH TOKEN =============================
    @PostMapping("/refresh-token")
    public ResponseEntity<String> refreshToken(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = null;
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }

            if (token == null) {
                return ResponseEntity.badRequest().body("No token provided");
            }

            String email = tokenService.extractUserEmail(token);
            String companyId = tokenService.extractCompanyId(token);

            if (email == null || companyId == null) {
                return ResponseEntity.status(401).body("Invalid token");
            }

            log.info("Refreshing token for: {}, {}", email, companyId);

            // Прямо передаем то, что вернул AdminService
            String url = String.format(
                    "http://localhost:8082/permissions/get-new-token/%s/%s",
                    companyId, email
            );

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, null, String.class
            );

            // Возвращаем ТОЧНО ТО ЖЕ, что вернул AdminService
            return ResponseEntity
                    .status(response.getStatusCode())
                    .body(response.getBody());

        } catch (Exception e) {
            log.error("Error: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Server error: " + e.getMessage());
        }
    }


    /// TODO : СДЕЛАТЬ ЗАПРОС, КОТОРЫЙ БУДЕТ ОБНОВЛЯТЬ ТОКЕН ПОСЛЕ ЕГО ИСТЧЕНИЯ

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

            // ПРОСТО извлекаем данные (даже из истекшего токена)
            String email = tokenService.extractUserEmail(token);
            String companyId = tokenService.extractCompanyId(token);

            if (email == null || companyId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid token data".getBytes());
            }

            // Проверяем права
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

            // Проксируем запрос
            return forwardRequest(targetUrl, request, body, permissionResponse, true);

        } catch (Exception e) {
            log.error("Gateway error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Gateway error: " + e.getMessage()).getBytes());
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

            // Добавляем флаг, что запрос аутентифицирован
            headers.add("X-Authenticated", "true");
        } else {
            // Для запросов без токена
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