package com.example.app_ldap.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests((requests) -> requests
                                                .requestMatchers("/css/**", "/js/**", "/*.js", "/images/**").permitAll()
                                                .requestMatchers("/", "/login", "/error",
                                                                "/registrazione", "/home",
                                                                "/registrazione/save")
                                                .permitAll()
                                                .requestMatchers("/gestisci").hasRole("ADMIN")
                                                .requestMatchers("/ordini").hasAnyRole("USER", "ADMIN")
                                                .anyRequest().authenticated())
                                .csrf(csrf -> csrf.disable())
                                .formLogin((form) -> form
                                                .loginPage("/login")
                                                .defaultSuccessUrl("/dashboard", true)
                                                .permitAll())
                                .logout(logout -> logout
                                                .logoutSuccessUrl("/login?logout")
                                                .permitAll());

                return http.build();
        }

        @Autowired
        public void configure(AuthenticationManagerBuilder auth, PasswordEncoder passwordEncoder) throws Exception {
                // Spring inietterà automaticamente il bean definito in PasswordConfig

                auth
                                .ldapAuthentication()
                                .userSearchBase("ou=people")
                                .userSearchFilter("(uid={0})")
                                .groupSearchBase("ou=group")
                                .groupSearchFilter("(memberUid={1})")
                                .contextSource()
                                .url("ldap://localhost:389/dc=mensa,dc=com")
                                .managerDn("cn=admin,dc=mensa,dc=com")
                                .managerPassword("admin")
                                .and()
                                .passwordCompare()
                                .passwordEncoder(passwordEncoder)
                                .passwordAttribute("userPassword");
        }
}