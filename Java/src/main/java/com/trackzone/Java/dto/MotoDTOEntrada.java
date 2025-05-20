package com.trackzone.Java.dto;

import com.trackzone.Java.model.StatusMoto;
import io.swagger.v3.oas.annotations.media.Schema;

public class MotoDTOEntrada {

    @Schema(example = "ABC-1234")
    private String placa;

    @Schema(example = "9BWZZZ377VT004251")
    private String chassi;

    @Schema(example = "MTR-98765")
    private String motor;

    @Schema(example = "Disponível")
    private StatusMoto status;

    @Schema(example = "A2")
    private String localizacao;

    public String getPlaca() {
        return placa;
    }

    public void setPlaca(String placa) {
        this.placa = placa;
    }

    public String getChassi() {
        return chassi;
    }

    public void setChassi(String chassi) {
        this.chassi = chassi;
    }

    public String getMotor() {
        return motor;
    }

    public void setMotor(String motor) {
        this.motor = motor;
    }

    public StatusMoto getStatus() {
        return status;
    }

    public void setStatus(StatusMoto status) {
        this.status = status;
    }

    public String getLocalizacao() {
        return localizacao;
    }

    public void setLocalizacao(String localizacao) {
        this.localizacao = localizacao;
    }
}
