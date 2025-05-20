package com.trackzone.Java.controller;

import com.trackzone.Java.dto.FilialDTO;
import com.trackzone.Java.dto.FilialResponseDTO;
import com.trackzone.Java.dto.LoginDTO;
import com.trackzone.Java.model.Filial;
import com.trackzone.Java.repository.FilialRepository;
import com.trackzone.Java.security.JWTUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/filiais")
@Tag(name = "Filiais", description = "Endpoints para cadastro e autenticação de filiais")
public class FilialController {

    @Autowired
    private FilialRepository filialRepository;

    @Autowired
    private JWTUtil jwtUtil;
    
    @Autowired
    private PasswordEncoder passwordEncoder;


    @Operation(summary = "Cadastrar nova filial")
    @PostMapping("/cadastrar")
    public ResponseEntity<FilialResponseDTO> cadastrar(@RequestBody @Valid FilialDTO dto) {
        Filial nova = new Filial();
        nova.setNome(dto.getNome());
        nova.setEmail(dto.getEmail());
        nova.setSenha(passwordEncoder.encode(dto.getSenha()));

        Filial salva = filialRepository.save(nova);
        FilialResponseDTO response = new FilialResponseDTO(salva.getId(), salva.getNome(), salva.getEmail());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }




    @Operation(summary = "Login da filial com JWT")
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDTO credenciais) {
        String email = credenciais.getEmail();
        String senha = credenciais.getSenha();

        Filial filial = filialRepository.findByEmail(email);
        if (filial != null && passwordEncoder.matches(senha, filial.getSenha())) {
            String token = jwtUtil.construirToken(email);
            return ResponseEntity.ok(token);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email ou senha inválidos");
    }

}
