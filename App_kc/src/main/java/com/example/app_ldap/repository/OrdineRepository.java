package com.example.app_ldap.repository;

import com.example.app_ldap.entity.Ordine;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrdineRepository extends MongoRepository<Ordine, String> {
    // Trova tutti gli ordini effettuati da un utente specifico
    List<Ordine> findByUsername(String username);
}
