package Adesk_Gateway.Models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionCheckRequest {
    private String email;
    private String companyId;
    private String service;        // "IDENTITY"
    private String path;           // "/api/checks/create"
    private String method;         // "POST", "GET", etc
    private Map<String, String> requestParams; // дополнительные параметры
}