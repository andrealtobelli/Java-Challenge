package security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SegurancaConfig {

    @SuppressWarnings("removal")
    @Bean
    SecurityFilterChain filtrarRota(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**", "/h2-console/**").permitAll()
                .anyRequest().authenticated()
            )
            .headers(headers -> headers
                .frameOptions(frame -> frame.disable())
            )
            .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    UserDetailsService gerarUsuario() {
        return new InMemoryUserDetailsManager(
            User.withUsername("admin")
                .password("{noop}1234")
                .roles("ADMIN")
                .build()
        );
    }
}
