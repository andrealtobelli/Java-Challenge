package com.trackzone.Java.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UsuarioConfig {
	
	@Bean
	UserDetailsService gerarUsuario() {
		
		UserDetailsService usuario = 
		new InMemoryUserDetailsManager(User
											.withUsername("admin")
											.password("{noop}1234")
											.roles("USER")
											.build());
		return usuario;	
	}

}
