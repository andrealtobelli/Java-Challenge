package com.trackzone.Java.config;

import com.trackzone.Java.model.StatusMoto;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class StatusMotoConverter implements Converter<String, StatusMoto> {

    @Override
    public StatusMoto convert(String source) {
        for (StatusMoto status : StatusMoto.values()) {
            if (status.getDescricao().equalsIgnoreCase(source) || status.name().equalsIgnoreCase(source)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Status inválido: " + source);
    }
}
