package Adesk_Gateway.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Отключаем CSRF для API
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Без сессий
                .authorizeHttpRequests(auth -> auth
                        // Публичные эндпоинты
//                        .requestMatchers("/api/test/**").permitAll()
//                        .requestMatchers("/api/gateway/company/accept-invite/**").permitAll()
//                        .requestMatchers("/actuator/health").permitAll()
//                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()

                        // Все остальные требуют аутентификации
                        .anyRequest().permitAll()
                )
                .httpBasic(httpBasic -> httpBasic.disable()); // Отключаем Basic Auth

        return http.build();
    }
}