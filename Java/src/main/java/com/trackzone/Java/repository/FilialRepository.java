package com.trackzone.Java.repository;

import com.trackzone.Java.model.Filial;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FilialRepository extends JpaRepository<Filial, Long> {
    Filial findByEmail(String email);
}
