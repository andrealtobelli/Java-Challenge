package com.trackzone.Java.repository;

import com.trackzone.Java.model.Moto;
import com.trackzone.Java.model.StatusMoto;
import com.trackzone.Java.projection.MotoStatusProjection;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;

public interface MotoRepository extends JpaRepository<Moto, Long> {

    long countByFilialId(Long filialId);

    long countByFilialIdAndStatus(Long filialId, StatusMoto status);

    @Query("SELECT COUNT(m) FROM Moto m WHERE m.filial.id = :filialId AND CAST(m.dataCheckin AS date) = :hoje")
    long countCheckinsDoDia(@Param("filialId") Long filialId, @Param("hoje") LocalDate hoje);

    @Query("SELECT COUNT(m) FROM Moto m WHERE m.filial.id = :filialId AND CAST(m.dataCheckout AS date) = :hoje")
    long countCheckoutsDoDia(@Param("filialId") Long filialId, @Param("hoje") LocalDate hoje);

    List<Moto> findTop5ByFilialIdOrderByDataCheckinDesc(Long filialId);

    Page<Moto> findByStatus(StatusMoto status, Pageable pageable);

    @Query("SELECT m.placa AS placa, m.status AS status, m.localizacao AS localizacao FROM Moto m WHERE m.status = :status")
    List<MotoStatusProjection> buscarPorStatusSimples(@Param("status") StatusMoto status);
}
