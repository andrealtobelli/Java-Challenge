package service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;

import dto.MotoDTO;
import model.Moto;
import model.StatusMoto;
import repository.MotoRepository;

@Service
public class MotoService {

    @Autowired
    private MotoRepository repository;

    @Cacheable("motos")
    public Page<MotoDTO> listar(String status, Pageable pageable) {
        Page<Moto> page;

        if (status == null) {
            page = repository.findAll(pageable);
        } else {
            try {
                StatusMoto statusEnum = StatusMoto.valueOf(status.toUpperCase());
                page = repository.findByStatus(statusEnum, pageable);
            } catch (IllegalArgumentException e) {
                return Page.empty(pageable);
            }
        }

        return page.map(MotoDTO::new);
    }

    public MotoDTO cadastrar(Moto moto) {
        Moto salvo = repository.save(moto);
        return new MotoDTO(salvo);
    }
}
