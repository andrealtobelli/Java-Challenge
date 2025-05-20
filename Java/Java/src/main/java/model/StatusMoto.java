package model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum StatusMoto {
	REPARO_SIMPLES("Reparo simples"),
    DANOS_ESTRUTURAIS("Danos estruturais"),
    DEFEITO_MOTOR("Defeito no motor"),
    SEM_PLACA("Sem placa"),
    EM_MANUTENCAO("Em manutenção"),
    PRONTA_PARA_ALUGAR("Pronta para alugar"),
    ALUGADA("Alugada"),
    AGUARDANDO_ALUGUEL("Aguardando aluguel");

    private final String descricao;

    StatusMoto(String descricao) {
        this.descricao = descricao;
    }

    @JsonValue
    public String getDescricao() {
        return descricao;
    }

    @Override
    public String toString() {
        return descricao;
    }
}
