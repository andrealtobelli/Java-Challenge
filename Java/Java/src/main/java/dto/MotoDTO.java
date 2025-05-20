package dto;

import model.Moto;
import model.StatusMoto;
import org.springframework.hateoas.RepresentationModel;

public class MotoDTO extends RepresentationModel<MotoDTO> {

    private Long id;
    private String placa;
    private String chassi;
    private String motor;
    private StatusMoto status;
    private String localizacao;

    public MotoDTO() {}

    public MotoDTO(Moto moto) {
        this.id = moto.getId();
        this.placa = moto.getPlaca();
        this.chassi = moto.getChassi();
        this.motor = moto.getMotor();
        this.status = moto.getStatus();
        this.localizacao = moto.getLocalizacao();
    }

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
}
