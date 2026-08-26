package br.com.spectre.spectrechat.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Cost 12: a few hundred milliseconds per verification, which is the point.
     * The value the client sends is already PBKDF2-stretched, so this is the
     * second of two deliberately slow steps.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // The API is called machine-to-machine with a bearer token in a
                // custom header, never from a browser session, so there is no
                // cookie for CSRF to attack.
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // InternalTokenFilter is what actually guards these; it
                        // runs ahead of the chain and rejects a bad token.
                        .requestMatchers("/internal/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().denyAll()
                );

        return http.build();
    }
}
