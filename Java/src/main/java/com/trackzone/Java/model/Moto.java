package com.trackzone.Java.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

@Entity
@Table(name = "moto")
public class Moto {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Schema(description = "Número da placa da moto", example = "ABC-1234")
    @Size(max = 10)
    private String placa;

    @Size(max = 17)
    private String chassi;

    @Size(max = 15)
    private String motor;

    @Enumerated(EnumType.STRING)
    private StatusMoto status;

    private String localizacao;

    @PastOrPresent(message = "Data de check-in não pode estar no futuro")
    private LocalDateTime dataCheckin;

    private LocalDateTime dataCheckout;

    @ManyToOne
    @JoinColumn(name = "filial_id")
    @JsonBackReference
    private Filial filial;

    // Getters e setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

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

    public LocalDateTime getDataCheckin() {
        return dataCheckin;
    }

    public void setDataCheckin(LocalDateTime dataCheckin) {
        this.dataCheckin = dataCheckin;
    }

    public LocalDateTime getDataCheckout() {
        return dataCheckout;
    }

    public void setDataCheckout(LocalDateTime dataCheckout) {
        this.dataCheckout = dataCheckout;
    }

    public Filial getFilial() {
        return filial;
    }

    public void setFilial(Filial filial) {
        this.filial = filial;
    }
}
