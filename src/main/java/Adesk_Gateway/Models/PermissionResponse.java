package Adesk_Gateway.Models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionResponse {
    private boolean allowed;
    private String reason;
    private String email;
    private String companyId;
    private List<String> permissions;     // ["PROJECTS_WORK"]
    private Map<String, Object> metadata; // дополнительные данные
}