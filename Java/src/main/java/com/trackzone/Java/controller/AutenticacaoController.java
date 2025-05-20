//package com.trackzone.Java.controller;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//
//import com.trackzone.Java.security.JWTUtil;
//
//@RestController
//@RequestMapping("/autenticacao")
//public class AutenticacaoController {
//	
//	@Autowired
//	private JWTUtil jwtUtil;
//	
//	@Autowired
//	private AuthenticationManager authenticationManager;
//	
//	@PostMapping("/login")
//	public String gerarTokenValido(@RequestParam String username, @RequestParam String password) {
//		try {
//			
//			var auth = new UsernamePasswordAuthenticationToken(username, password);
//			authenticationManager.authenticate(auth);
//			return jwtUtil.construirToken(username);
//			
//			
//		} catch (Exception e) {
//			return "Usuário ou senha inválidos";
//		}
//		
//	}
//}
