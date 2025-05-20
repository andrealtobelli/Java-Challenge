package com.trackzone.Java.dto;

import com.trackzone.Java.dto.MotoDTO;
import java.util.List;

public class DashboardDTO {

    private long totalMotos;
    private long disponiveis;
    private long emManutencao;
    private long alugadas;
    private long checkinsHoje;
    private long checkoutsHoje;
    private String nomeFilial;
    private List<MotoDTO> ultimasAtividades;

    public long getTotalMotos() {
        return totalMotos;
    }

    public void setTotalMotos(long totalMotos) {
        this.totalMotos = totalMotos;
    }

    public long getDisponiveis() {
        return disponiveis;
    }

    public void setDisponiveis(long disponiveis) {
        this.disponiveis = disponiveis;
    }

    public long getEmManutencao() {
        return emManutencao;
    }

    public void setEmManutencao(long emManutencao) {
        this.emManutencao = emManutencao;
    }

    public long getAlugadas() {
        return alugadas;
    }

    public void setAlugadas(long alugadas) {
        this.alugadas = alugadas;
    }

    public long getCheckinsHoje() {
        return checkinsHoje;
    }

    public void setCheckinsHoje(long checkinsHoje) {
        this.checkinsHoje = checkinsHoje;
    }

    public long getCheckoutsHoje() {
        return checkoutsHoje;
    }

    public void setCheckoutsHoje(long checkoutsHoje) {
        this.checkoutsHoje = checkoutsHoje;
    }

    public String getNomeFilial() {
        return nomeFilial;
    }

    public void setNomeFilial(String nomeFilial) {
        this.nomeFilial = nomeFilial;
    }

    public List<MotoDTO> getUltimasAtividades() {
        return ultimasAtividades;
    }

    public void setUltimasAtividades(List<MotoDTO> ultimasAtividades) {
        this.ultimasAtividades = ultimasAtividades;
    }
} 