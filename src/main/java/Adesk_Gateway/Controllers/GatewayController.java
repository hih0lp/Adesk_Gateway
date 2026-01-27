package Adesk_Gateway.Controllers;

import Adesk_Gateway.Models.PermissionCheckRequest;
import Adesk_Gateway.Models.PermissionResponse;
import Adesk_Gateway.Services.TokenService;
import Adesk_Gateway.Client.AdminServiceClient;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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
public class GatewayController {

    private final RestTemplate restTemplate;
    private final TokenService tokenService;
    private final AdminServiceClient adminServiceClient;


    @Value("${SERVICE_ADMIN_URL}")
    private String adminServiceUrl;

    @Value("${SERVICE_IDENTITY_URL}")
    private String identityServiceUrl;

    @Value("${SERVICE_PROJECT_URL}")
    private String projectServiceUrl;

    @Value("${SERVICE_OPERATION_URL}")
    private String operationServiceUrl;

    @Value("${SERVICE_COUNTERPARTY_URL}")
    private String counterpartyServiceUrl;


    // ==================== CHECKS SERVICE ====================
    @PostMapping("/checks/create-category")
    public ResponseEntity<?> createCheckCategoryAsync(@RequestBody Object body,
                                                      HttpServletRequest request) {
        String url = adminServiceUrl + "/checks/create-category";
        return forwardWithPermissionCheck(url, request, body);
    }

    @DeleteMapping("/checks/delete-category")
    public ResponseEntity<?> deleteCheckCategoryAsync(@RequestBody Object body,
                                                      HttpServletRequest request) {
        String url = adminServiceUrl + "/checks/delete-category";
        return forwardWithPermissionCheck(url, request, body);
    }

    @PostMapping("/checks/create-check")
    public ResponseEntity<?> createCheckAsync(@RequestBody Object body,
                                              HttpServletRequest request) {
        String url = adminServiceUrl + "/checks/create-check";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/checks/get-categories-by-company-id/{companyId}")
    public ResponseEntity<?> getCheckCategoriesByCompanyIdAsync(@PathVariable String companyId,
                                                                HttpServletRequest request) {
        String url = adminServiceUrl + "/checks/get-categories-by-company-id/" + companyId;
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/checks/get-checks-by-company-id/{companyId}")
    public ResponseEntity<?> getChecksByCompanyIdAsync(@PathVariable String companyId,
                                                       HttpServletRequest request) {
        String url = adminServiceUrl + "/checks/get-checks-by-company-id/" + companyId;
        return forwardWithPermissionCheck(url, request, null);
    }

    // ==================== COMPANY SERVICE ====================
    @PostMapping("/company/invite-member")
    public ResponseEntity<?> inviteMemberAsync(@RequestBody Object body,
                                               HttpServletRequest request) {
        String url = adminServiceUrl + "/company/invite-member";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/company/accept-invite/{token}")
    public ResponseEntity<?> acceptInviteAsync(@PathVariable String token,
                                               HttpServletRequest request) {
        String url = adminServiceUrl + "/company/accept-invite/" + token;
        return forwardRequest(url, request, null, null, false);
    }

    @PutMapping("/company/edit-company-name")
    public ResponseEntity<?> editCompanyNameAsync(@RequestBody Object body,
                                                  HttpServletRequest request){
        String url = adminServiceUrl + "/company/edit-company-name";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/company/get-user-companies-by-email/{userEmail}")
    public ResponseEntity<?> getCompaniesByUserEmailAsync(@PathVariable String userEmail,
                                                          HttpServletRequest request){
        String url = adminServiceUrl + "/company/get-user-companies-by-email/" + userEmail;
        return forwardRequest(url, request, null, null, false);
    }

    @PutMapping("/company/edit-user-rights")
    public ResponseEntity<?> editUserRightsAsync(@RequestBody Object body,
                                                 HttpServletRequest request){
        String url = adminServiceUrl + "/company/edit-user-rights";
        return forwardWithPermissionCheck(url, request, body);
    }

    @DeleteMapping("/company/delete-user-from-company/{companyId}/{userEmail}")
    public ResponseEntity<?> deleteUserFromCompanyAsync(@PathVariable String companyId,
                                                        @PathVariable String userEmail,
                                                        HttpServletRequest request){
        String url = adminServiceUrl + "/company/delete-user-from-company/" + companyId + "/" + userEmail;
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/company/is-company-exist/{companyId}")
    public ResponseEntity<?> isCompanyExistAsync(@PathVariable String companyId, HttpServletRequest request){
        String url = adminServiceUrl + "/company/is-company-exist/" + companyId;
        return forwardRequest(url, request, null, null, false);
    }

    @PostMapping("/company/create-company/{userEmail}")
    public ResponseEntity<?> createCompanyAsync(@PathVariable String userEmail, @RequestBody Object body, HttpServletRequest request){
        String url = adminServiceUrl + "/company/create-company/" + userEmail;
        return forwardRequest(url, request, body, null, false);
    }

    // ==================== PROJECT SERVICE ===========================
    @PostMapping("/projects/create-category")
    public ResponseEntity<?> createProjectCategoryAsync(@RequestBody Object body, HttpServletRequest request){
        String url = projectServiceUrl + "/projects/create-category";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/projects/get-projects-by-date")
    public ResponseEntity<?> getProjectsOrderByDateAsync(HttpServletRequest request){
        String url = projectServiceUrl + "/projects/get-projects-by-date";
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/projects/get-projects-order-by-char")
    public ResponseEntity<?> getProjectsOrderByCharAsync(HttpServletRequest request){
        String url = projectServiceUrl + "/projects/get-projects-order-by-char";
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/projects/get-responsible-projects/{responsibleLogin}")
    public ResponseEntity<?> getResponsibleProjects(@PathVariable String responsibleLogin, HttpServletRequest request){
        String url = projectServiceUrl + "/projects/get-responsible-projects/" + responsibleLogin;
        return forwardWithPermissionCheck(url, request, null);
    }

    @DeleteMapping("/projects/delete-category")
    public ResponseEntity<?> deleteCategoryAsync(@RequestBody Object body, HttpServletRequest request){
        String url = projectServiceUrl + "/projects/delete-category";
        return forwardWithPermissionCheck(url, request, body);
    }

    @PostMapping("/projects/create-project")
    public ResponseEntity<?> createProjectAsync(@RequestBody Object body, HttpServletRequest request){
        String url = projectServiceUrl + "/projects/create-project";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/projects/get-company-projects")
    public ResponseEntity<?> getCompanyProjects(HttpServletRequest request){
        String url = projectServiceUrl + "/projects/get-company-projects";
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/projects/get-project-categories")
    public ResponseEntity<?> getCompanyProjectsCategories(HttpServletRequest request){
        String url = projectServiceUrl + "/projects/get-project-categories";
        return forwardWithPermissionCheck(url, request, null);
    }

    @DeleteMapping("/projects/delete-project")
    public ResponseEntity<?> deleteProjectAsync(@RequestBody Object body, HttpServletRequest request){
        String url = projectServiceUrl + "/projects/delete-project";
        return forwardWithPermissionCheck(url, request, body);
    }

    // ==================== OPERATION SERVICE ==========================
    @PostMapping("/requests/create-request")
    public ResponseEntity<?> createOperationAsync(@RequestBody Object body, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/create-request";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/requests/get-operations-by-project/{projectName}")
    public ResponseEntity<?> getProjectOperationsAsync(@PathVariable String projectName, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-operations-by-project/" + projectName;
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/requests/get-project-statistic/{projectName}")
    public ResponseEntity<?> getProjectStatistic(@PathVariable String projectName, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-project-statistic/" + projectName;
        return forwardWithPermissionCheck(url, request, null);
    }

    @DeleteMapping("/requests/delete-requests")
    public ResponseEntity<?> deleteOperationsAsync(@RequestBody Object body, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/delete-requests";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/requests/get-requests")
    public ResponseEntity<?> getRequestsByProjectNameAsync(HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-requests";
        return forwardWithPermissionCheck(url, request, null);
    }

    @PostMapping("/requests/approve-request/{requestId}")
    public ResponseEntity<?> approveRequestAsync(@PathVariable String requestId, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/approve-request/" + requestId;
        return forwardWithPermissionCheck(url, request, null);
    }

    @PostMapping("/requests/disapprove-request/{requestId}")
    public ResponseEntity<?> disapproveRequestAsync(@PathVariable String requestId, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/disapprove-request/" + requestId;
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/requests/get-requests-order-by-date-today")
    public ResponseEntity<?> getRequestsOrderByDateToday(HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-requests-order-by-date-today";
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/requests/get-requests-order-by-date-week")
    public ResponseEntity<?> getRequestsOrderByDateWeek(HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-requests-order-by-date-week";
        return forwardWithPermissionCheck(url, request, null);
    }

    @PostMapping("/requests/get-requests-order-by-dates")
    public ResponseEntity<?> getRequestsOrderByDates(@RequestBody Object body, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-requests-order-by-dates";
        return forwardWithPermissionCheck(url, request, body);
    }

    @GetMapping("/requests/get-requests-order-by-date-quarter/{numberOfQuarter}")
    public ResponseEntity<?> getRequestsOrderByQuarter(@PathVariable String numberOfQuarter, HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-requests-order-by-date-quarter/" + numberOfQuarter;
        return forwardWithPermissionCheck(url, request, null);
    }

    @GetMapping("/requests/get-requests-order-by-date-year")
    public ResponseEntity<?> getRequestsOrderByYear(HttpServletRequest request){
        String url = operationServiceUrl + "/requests/get-requests-order-by-date-year";
        return forwardWithPermissionCheck(url, request, null);
    }

    // ==================== IDENTITY SERVICE ==========================
    @PostMapping("/auth/registrate-user")
    public ResponseEntity<?> registrateUserAsync(@RequestBody Object body, HttpServletRequest request){
        String url = identityServiceUrl + "/auth/registrate-user";
        return forwardRequest(url, request, body, null, false);
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> logInAndSendAuthCodeAsync(@RequestBody Object body, HttpServletRequest request){
        String url = identityServiceUrl + "/auth/login";
        return forwardRequest(url, request, body, null, false);
    }

    @PostMapping("/auth/verify-code")
    public ResponseEntity<?> verifyUserAsync(@RequestBody Object body, HttpServletRequest request){
        String url = identityServiceUrl + "/auth/verify-code";
        return forwardRequest(url, request, body, null, false);
    }

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

            String url = adminServiceUrl + "/permissions/get-new-token/" + companyId + "/" + email;
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, null, String.class
            );

            return ResponseEntity
                    .status(response.getStatusCode())
                    .body(response.getBody());

        } catch (Exception e) {
            log.error("Error: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Server error: " + e.getMessage());
        }
    }

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

            String email = tokenService.extractUserEmail(token);
            String companyId = tokenService.extractCompanyId(token);

            if (email == null || companyId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid token data".getBytes());
            }

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

            return forwardRequest(targetUrl, request, body, permissionResponse, true);

        } catch (Exception e) {
            log.error("Gateway error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Gateway error: " + e.getMessage()).getBytes());
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
            log.warn("Target service returned {}: {}", e.getStatusCode(), e.getStatusText());
            return ResponseEntity
                    .status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsByteArray());

        } catch (HttpServerErrorException e) {
            log.error("Target service error {}: {}", e.getStatusCode(), e.getStatusText());
            return ResponseEntity
                    .status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsByteArray());

        } catch (Exception e) {
            log.error("Gateway forwarding error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("Gateway error: Service unavailable".getBytes());
        }
    }

    private HttpHeaders buildHeaders(HttpServletRequest request,
                                     PermissionResponse permissionResponse,
                                     boolean withToken) {
        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!shouldSkipHeader(headerName)) {
                headers.add(headerName, request.getHeader(headerName));
            }
        }

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