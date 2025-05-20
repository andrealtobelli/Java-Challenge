package service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import dto.MotoDTO;
import model.Moto;
import repository.MotoRepository;

@Service
public class MotoPaginacaoService {

    @Autowired
    private MotoRepository repository;

    public Page<MotoDTO> paginar(Pageable pageable) {
        Page<Moto> motos = repository.findAll(pageable);
        return motos.map(MotoDTO::new); // converte cada Moto para MotoDTO usando o construtor
    }
}
