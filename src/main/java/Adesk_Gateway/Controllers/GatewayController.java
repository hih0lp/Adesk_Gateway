package Adesk_Gateway.Controllers;

import Adesk_Gateway.Models.PermissionCheckRequest;
import Adesk_Gateway.Models.PermissionResponse;
import Adesk_Gateway.Services.TokenService;
import Adesk_Gateway.Client.AdminServiceClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/gateway")
@RequiredArgsConstructor
public class GatewayController {

    private final RestTemplate restTemplate;
    private final TokenService tokenService;
    private final AdminServiceClient adminServiceClient;

    // ==================== CHECKS SERVICE ====================
    @PostMapping("/checks/create-category")
    public ResponseEntity<?> createCheckCategory(@RequestBody Object body,
                                         HttpServletRequest request) {
        return forwardWithPermissionCheck(
                "checks",
                "http://localhost:8082/checks/create-category",
                request,
                body
        );
    }


    @PostMapping("/checks/create-check")
    public ResponseEntity<?> createCheck(@RequestBody Object body,
                                         HttpServletRequest request) {
        return forwardWithPermissionCheck(
                "checks",
                "http://localhost:8082/checks/create-check",
                request,
                body
        );
    }


    @DeleteMapping("/checks/{id}")
    public ResponseEntity<?> deleteCheck(@PathVariable Long id,
                                         HttpServletRequest request) {
        return forwardWithPermissionCheck(
                "checks",
                "http://localhost:8083/api/checks/" + id,
                request,
                null
        );
    }

    // ==================== COMPANY SERVICE ====================

    @PostMapping("/company/invite-member")
    public ResponseEntity<?> inviteMember(@RequestBody Object body,
                                          HttpServletRequest request) {
        return forwardWithPermissionCheck(
                "admin",
                "http://localhost:8082/company/invite-member",
                request,
                body
        );
    }

    // ==================== PUBLIC ENDPOINTS ====================

    @GetMapping("/company/accept-invite/{token}")
    public ResponseEntity<?> acceptInvite(@PathVariable String token,
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

    // ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    /**
     * Метод с проверкой токена и прав доступа
     */
    private ResponseEntity<?> forwardWithPermissionCheck(String service, //имя сервиса
                                                         String targetUrl, //куда отправляем
                                                         HttpServletRequest request, //что получили от клиента
                                                         Object body) { //тело запроса
        try {
            String token = extractToken(request);
            if (token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED) //если запрос с токеном и токена нет, тогда 401
                        .body("Missing authorization token");
            }


            String email = tokenService.extractUserEmail(token);
            String companyId = tokenService.extractCompanyId(token);

            if (email == null || companyId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid token data");
            }

            Map<String, String> requestParams = extractRequestParams(request);

            // создание запроса на проверку прав
            PermissionCheckRequest permissionRequest = PermissionCheckRequest.builder()
                    .email(email)
                    .companyId(companyId)
                    .service(service)
                    .path(request.getRequestURI())
                    .method(request.getMethod())
                    .requestParams(requestParams)
                    .build();


            PermissionResponse permissionResponse = adminServiceClient
                    .checkPermissions(permissionRequest);

            if (!permissionResponse.isAllowed()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Access denied: " + permissionResponse.getReason());
            }

            //кидаю запрос в нужный сервис
            return forwardRequest(targetUrl, request, body, permissionResponse, true);

        } catch (Exception e) {
            log.error("Gateway error with token check: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Gateway error: " + e.getMessage());
        }
    }

    //без проверки токена - если методы не в компании или еще чето
    private ResponseEntity<?> forwardWithoutToken(String targetUrl,
                                                  HttpServletRequest request,
                                                  Object body) {
        try {
            // Проксируем запрос без проверки токена и прав
            return forwardRequest(targetUrl, request, body, null, false);

        } catch (Exception e) {
            log.error("Gateway error without token check: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Gateway error: " + e.getMessage());
        }
    }

    //в целом перенаправляет все запросы, удобно
    private ResponseEntity<?> forwardRequest(String targetUrl,
                                             HttpServletRequest request,
                                             Object body,
                                             PermissionResponse permissionResponse,
                                             boolean withToken) {
        try {
            // 1. Создаем заголовки
            HttpHeaders headers = buildHeaders(request, permissionResponse, withToken);

            // 2. Проксируем запрос
            HttpMethod method = HttpMethod.valueOf(request.getMethod());
            HttpEntity<Object> entity = new HttpEntity<>(body, headers);

            ResponseEntity<byte[]> response = restTemplate.exchange(
                    targetUrl,
                    method,
                    entity,
                    byte[].class
            );

            // 3. Возвращаем ответ
            return ResponseEntity
                    .status(response.getStatusCode())
                    .headers(cleanHeaders(response.getHeaders()))
                    .body(response.getBody());

        } catch (Exception e) {
            log.error("Forward request error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Forwarding error: " + e.getMessage());
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