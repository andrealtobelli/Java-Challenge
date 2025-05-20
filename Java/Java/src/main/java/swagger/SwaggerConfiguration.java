package swagger;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;

@Configuration
public class SwaggerConfiguration {

    @Bean
    OpenAPI configurarSwagger() {
        return new OpenAPI().info(new Info()
            .title("TrackZone - Gestão de Motos em Pátios")
            .description("API para controle e monitoramento de motos em pátios de filiais. Permite check-in, check-out, localização, histórico e status das motos.")
            .summary("Sistema de gestão para check-in/out de motos em filiais com controle de status e localização.")
            .version("v1.0.0")
            .license(new License()
                .name("TrackZone License")
                .url("https://github.com/SeuRepositorio/TrackZone"))
            .termsOfService("https://github.com/SeuRepositorio/TrackZone/terms"));
    }
}
