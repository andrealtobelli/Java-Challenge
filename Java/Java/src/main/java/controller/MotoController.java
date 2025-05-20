package controller;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.*;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.data.domain.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import dto.MotoDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import model.Moto;
import model.StatusMoto;
import repository.MotoRepository;
import service.MotoCachingService;
import service.MotoPaginacaoService;

@RestController
@RequestMapping("/motos")
@Tag(name = "Motos", description = "Endpoints para gerenciamento de motos no pátio")
public class MotoController {

    @Autowired
    private MotoRepository repository;

    @Autowired
    private MotoPaginacaoService paginacaoService;

    @Autowired
    private MotoCachingService cacheService;

    @Operation(summary = "Listar todas as motos")
    @GetMapping("/todas_cacheable")
    public List<MotoDTO> listarTodas() {
        List<Moto> motos = cacheService.findAll();

        return motos.stream().map(m -> {
            MotoDTO dto = new MotoDTO(m); // <-- aqui precisa existir o construtor correto
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

    @Operation(summary = "Inserir uma nova moto")
    @PostMapping("/inserir")
    @CacheEvict(value = "motos", allEntries = true)
    public Moto inserir(@RequestBody Moto moto) {
        Moto salva = repository.save(moto);
        cacheService.limparCache();
        return salva;
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
