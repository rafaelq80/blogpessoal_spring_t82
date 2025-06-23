package com.generation.blogpessoal.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class BasicSecurityConfig {

	private static final String[] SWAGGER_LIST = {
			"/",
	        "/docs",
			"/swagger-ui/**",
		    "/v3/api-docs/**",
		    "/swagger-resources/**",
	};

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    	http
	        .sessionManagement(management -> management
	                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        		.csrf(csrf -> csrf.disable())
	        		.anonymous(anonymous -> anonymous.disable())
	        		.cors(withDefaults());

    	http
	        .authorizeHttpRequests((auth) -> auth
	                .requestMatchers("/usuarios/logar").permitAll()
	                .requestMatchers("/usuarios/cadastrar").permitAll()
	                .requestMatchers("/error/**").permitAll()
	                .requestMatchers(HttpMethod.OPTIONS).permitAll()
	                .requestMatchers(SWAGGER_LIST).permitAll()
	                .anyRequest().authenticated())
	        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
	        .exceptionHandling(exceptions -> exceptions
	        		.authenticationEntryPoint((request, response, authException) -> {
		                response.setStatus(401);
		                response.setContentType("application/json");
		                response.getWriter().write(getAuthenticationErrorMessage(request.getRequestURI()));
		            }))
	        .httpBasic(withDefaults());

		return http.build();

    }
    
    private String getAuthenticationErrorMessage(String requestPath) {
        if ("/usuarios/logar".equals(requestPath)) {
            return "{\"error\":\"Credenciais (e-mail e/ou senha) inválidas\",\"status\":401}";
        } else if ("/usuarios/cadastrar".equals(requestPath)) {
            return "{\"error\":\"Dados de cadastro inválidos\",\"status\":401}";
        } else {
            return "{\"error\":\"Token de acesso requerido\",\"status\":401}";
        }
    }

}