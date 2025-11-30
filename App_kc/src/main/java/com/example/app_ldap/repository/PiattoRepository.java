package com.example.app_ldap.repository;

import com.example.app_ldap.entity.Piatto;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface PiattoRepository extends MongoRepository<Piatto, String> {

    List<Piatto> findByCategoria(String categoria);
}