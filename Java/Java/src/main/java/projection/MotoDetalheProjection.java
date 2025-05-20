package projection;

public interface MotoDetalheProjection {
    String getPlaca();
    String getChassi();
    String getMotor();
    String getStatus();
    String getLocalizacao();
    String getNome(); // nome da filial (JOIN)
}