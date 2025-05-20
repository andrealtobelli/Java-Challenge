package repository;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import model.Moto;
import model.StatusMoto;
import projection.MotoDetalheProjection;
import projection.MotoStatusProjection;

public interface MotoRepository extends JpaRepository<Moto, Long> {

    // Paginação por status
	Page<Moto> findByStatus(StatusMoto status, Pageable pageable);


    // Projeção simples
    List<MotoStatusProjection> buscarPorStatusSimples(String status);

    // Projeção detalhada com JOIN
    @Query("SELECT m.placa AS placa, m.status AS status, m.localizacao AS localizacao, f.nome AS nome " +
           "FROM Moto m JOIN m.filial f WHERE m.id = :id")
    MotoDetalheProjection buscarDetalhesDaMoto(@Param("id") Long id);

    // Motos com data de check-in recente
    @Query("FROM Moto m WHERE m.dataCheckin >= :data")
    List<Moto> buscarMotosRecentes(@Param("data") LocalDate data);

    // Consulta por parte da placa (ignorando maiúsculas/minúsculas)
    @Query(nativeQuery = true,
           value = "SELECT placa, status, localizacao FROM moto WHERE upper(placa) LIKE concat('%', upper(:placa), '%')")
    List<MotoStatusProjection> buscarPorParteDaPlaca(@Param("placa") String placa);
}
