package com.trackzone.Java.controller;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.*;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.data.domain.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import com.trackzone.Java.dto.MotoDTO;
import com.trackzone.Java.dto.MotoDTOEntrada;
import com.trackzone.Java.model.Moto;
import com.trackzone.Java.model.StatusMoto;
import com.trackzone.Java.repository.MotoRepository;
import com.trackzone.Java.security.JWTUtil;
import com.trackzone.Java.service.MotoCachingService;
import com.trackzone.Java.service.MotoPaginacaoService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import com.trackzone.Java.model.Filial;
import com.trackzone.Java.repository.FilialRepository;
import com.trackzone.Java.dto.MotoDTO;

import java.time.LocalDateTime;



@RestController
@RequestMapping("/motos")
@Tag(name = "Motos", description = "Endpoints para gerenciamento de motos no pátio")
public class MotoController {

	@Autowired
	private JWTUtil jwtUtil;

    @Autowired
    private MotoRepository repository;

    @Autowired
    private MotoPaginacaoService paginacaoService;

    @Autowired
    private MotoCachingService cacheService;
    
    @Autowired
    private FilialRepository filialRepository;


    @Operation(summary = "Listar todas as motos")
    @GetMapping("/todas_cacheable")
    public List<MotoDTO> listarTodas() {
        List<Moto> motos = cacheService.findAll();

        return motos.stream().map(m -> {
            MotoDTO dto = new MotoDTO(m);
            dto.add(linkTo(methodOn(MotoController.class).buscarPorId(m.getId()))
                     .withRel("Detalhes da moto"));
            return dto;
        }).toList();
    }

    @Operation(summary = "Buscar moto por ID")
    @GetMapping("/{id}")
    public Moto buscarPorId(@PathVariable Long id) {
        return cacheService.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Moto não encontrada"));
    }

    @PostMapping("/inserir")
    @CacheEvict(value = "motos", allEntries = true)
    public ResponseEntity<Moto> inserir(@RequestBody MotoDTOEntrada dto, @RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "").trim();
            String email = jwtUtil.extrairUsername(token);

            Filial filial = filialRepository.findByEmail(email);
            if (filial == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
            }

            Moto moto = new Moto();
            moto.setPlaca(dto.getPlaca());
            moto.setChassi(dto.getChassi());
            moto.setMotor(dto.getMotor());
            moto.setLocalizacao(dto.getLocalizacao());
            moto.setStatus(dto.getStatus());
            moto.setDataCheckin(LocalDateTime.now());
            moto.setFilial(filial);

            Moto salva = repository.save(moto);
            cacheService.limparCache();

            return ResponseEntity.status(HttpStatus.CREATED).body(salva);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }



    @Operation(summary = "Atualizar uma moto")
    @PutMapping("/atualizar/{id}")
    @CacheEvict(value = "motos", allEntries = true)
    public Moto atualizar(@RequestBody Moto moto, @PathVariable Long id) {
        return cacheService.findById(id).map(atual -> {
            atual.setPlaca(moto.getPlaca());
            atual.setChassi(moto.getChassi());
            atual.setMotor(moto.getMotor());
            atual.setStatus(moto.getStatus());
            atual.setLocalizacao(moto.getLocalizacao());
            Moto atualizado = repository.save(atual);
            cacheService.limparCache();
            return atualizado;
        }).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @Operation(summary = "Remover uma moto")
    @DeleteMapping("/remover/{id}")
    @CacheEvict(value = "motos", allEntries = true)
    public Moto remover(@PathVariable Long id) {
        return cacheService.findById(id).map(moto -> {
            repository.delete(moto);
            cacheService.limparCache();
            return moto;
        }).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @Operation(summary = "Listar motos paginadas")
    @GetMapping("/paginadas")
    public ResponseEntity<Page<MotoDTO>> paginadas(
            @RequestParam(defaultValue = "0") int pagina,
            @RequestParam(defaultValue = "5") int tamanho) {

        PageRequest req = PageRequest.of(pagina, tamanho);
        Page<MotoDTO> page = paginacaoService.paginar(req);

        page.forEach(dto -> dto.add(linkTo(methodOn(MotoController.class)
                .buscarPorId(dto.getId()))
                .withRel("Ver detalhes")));

        return ResponseEntity.ok(page);
    }

    @Operation(summary = "Filtrar por status")
    @GetMapping("/status")
    public ResponseEntity<Page<MotoDTO>> buscarPorStatus(
            @RequestParam StatusMoto status,
            @RequestParam(defaultValue = "0") int pagina,
            @RequestParam(defaultValue = "5") int tamanho) {

        Pageable pageable = PageRequest.of(pagina, tamanho, Sort.by("id"));
        Page<Moto> motos = repository.findByStatus(status, pageable);
        Page<MotoDTO> page = motos.map(MotoDTO::new);

        return ResponseEntity.ok(page);
    }

}
