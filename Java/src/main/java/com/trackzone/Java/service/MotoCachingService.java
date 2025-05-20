package com.trackzone.Java.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.trackzone.Java.model.Moto;
import com.trackzone.Java.model.StatusMoto;
import com.trackzone.Java.projection.MotoStatusProjection;
import com.trackzone.Java.repository.MotoRepository;

@Service
public class MotoCachingService {

    @Autowired
    private MotoRepository repository;

    @Cacheable(value = "motos_all")
    public List<Moto> findAll() {
        return repository.findAll();
    }

    @Cacheable(value = "motos_paginadas", key = "#pageable")
    public Page<Moto> findAll(Pageable pageable) {
        return repository.findAll(pageable);
    }

    @Cacheable(value = "motos_por_status", key = "#status")
    public List<MotoStatusProjection> findByStatus(String status) {
        try {
            StatusMoto statusEnum = StatusMoto.valueOf(status.toUpperCase());
            return repository.buscarPorStatusSimples(statusEnum);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Status informado é inválido: " + status);
        }
    }

    @Cacheable(value = "moto_por_id", key = "#id")
    public Optional<Moto> findById(Long id) {
        return repository.findById(id);
    }

    @CacheEvict(value = { "motos_all", "motos_paginadas", "motos_por_status", "moto_por_id" }, allEntries = true)
    public void limparCache() {
        System.out.println("Cache limpo com sucesso!");
    }

}
