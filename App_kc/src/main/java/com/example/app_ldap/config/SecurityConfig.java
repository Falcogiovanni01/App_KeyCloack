package com.example.app_ldap.config;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests(auth -> auth
                                                // 1. Risorse statiche e Home (Pubbliche)
                                                .requestMatchers("/", "/css/**", "/js/**", "/images/**", "/error")
                                                .permitAll()

                                                // 2. Protezione Pagine basata sui Ruoli (letti da Keycloak)
                                                .requestMatchers("/gestione").hasRole("ADMIN")
                                                .requestMatchers("/ordini").hasAnyRole("USER", "ADMIN")

                                                // 3. Tutto il resto richiede login
                                                .anyRequest().authenticated())
                                .csrf(csrf -> csrf.disable()) // Opzionale, per semplicità

                                // --- OAUTH2 LOGIN (Il cuore di Keycloak) ---
                                .oauth2Login(oauth2 -> oauth2
                                                .defaultSuccessUrl("/dashboard", true) // Dopo il login su Keycloak,
                                                                                       // torna qui
                                                .userInfoEndpoint(userInfo -> userInfo
                                                                .userAuthoritiesMapper(userAuthoritiesMapper()) // per
                                                                                                                // leggere
                                                                                                                // i
                                                                                                                // ruoli
                                                                                                                // //
                                                                                                                // QUI

                                                ))

                                // --- LOGOUT ---
                                // Logout standard di Spring
                                .logout(logout -> logout
                                                .logoutSuccessUrl("/")
                                                .permitAll());

                return http.build();
        }

        /**
         * QUESTO È IL TUO "@GETROLE"
         * Serve a tradurre i ruoli di Keycloak in ruoli che Spring capisce.
         * Keycloak invia i ruoli dentro il JSON del token, noi li estraiamo e ci
         * mettiamo "ROLE_" davanti.
         */
        @Bean
        public GrantedAuthoritiesMapper userAuthoritiesMapper() {
                return (authorities) -> {
                        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                        authorities.forEach(authority -> {
                                if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                                        Map<String, Object> userInfo = oidcUserAuthority.getAttributes();

                                        // Cerca la sezione "realm_access" nel token (dove Keycloak mette i ruoli
                                        // globali)
                                        Map<String, Object> realmAccess = (Map<String, Object>) userInfo
                                                        .get("realm_access");

                                        if (realmAccess != null) {
                                                Collection<String> roles = (Collection<String>) realmAccess
                                                                .get("roles");
                                                if (roles != null) {
                                                        // Converte ogni ruolo (es. "admin") in "ROLE_ADMIN"
                                                        mappedAuthorities.addAll(roles.stream()
                                                                        .map(roleName -> new SimpleGrantedAuthority(
                                                                                        "ROLE_" + roleName
                                                                                                        .toUpperCase()))
                                                                        .collect(Collectors.toList()));
                                                }
                                        }
                                }
                        });
                        return mappedAuthorities;
                };
        }
}