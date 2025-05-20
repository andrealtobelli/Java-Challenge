package com.trackzone.Java.controller;

import com.trackzone.Java.dto.DashboardDTO;
import com.trackzone.Java.dto.MotoDTO;
import com.trackzone.Java.model.StatusMoto;
import com.trackzone.Java.repository.FilialRepository;
import com.trackzone.Java.repository.MotoRepository;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@RestController
@RequestMapping("/dashboard")
@Tag(name = "Dashboard", description = "Resumo operacional da filial")
public class DashboardController {

    @Autowired
    private MotoRepository motoRepository;

    @Autowired
    private FilialRepository filialRepository;

    @GetMapping("/{filialId}")
    public DashboardDTO getDashboard(@PathVariable Long filialId) {
        DashboardDTO dto = new DashboardDTO();

        dto.setTotalMotos(motoRepository.countByFilialId(filialId));
        dto.setDisponiveis(motoRepository.countByFilialIdAndStatus(filialId, StatusMoto.DISPONIVEL));
        dto.setEmManutencao(motoRepository.countByFilialIdAndStatus(filialId, StatusMoto.EM_MANUTENCAO));
        dto.setAlugadas(motoRepository.countByFilialIdAndStatus(filialId, StatusMoto.ALUGADA));
        dto.setCheckinsHoje(motoRepository.countCheckinsDoDia(filialId, LocalDate.now()));
        dto.setCheckoutsHoje(motoRepository.countCheckoutsDoDia(filialId, LocalDate.now()));

        dto.setNomeFilial(
            filialRepository.findById(filialId)
                .map(f -> f.getNome())
                .orElse("Filial não encontrada")
        );

        dto.setUltimasAtividades(
            motoRepository.findTop5ByFilialIdOrderByDataCheckinDesc(filialId)
                .stream().map(MotoDTO::new).toList()
        );

        return dto;
    }
}