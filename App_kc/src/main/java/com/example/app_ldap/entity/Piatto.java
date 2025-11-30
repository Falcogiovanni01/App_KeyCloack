package com.example.app_ldap.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Lombok genera Getters, Setters e ToString automaticamente
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "piatti") // Dice a Mongo: "Salva questi oggetti nella collezione 'piatti'"
public class Piatto {

    @Id
    private String id;
    private String nome;
    private String categoria;
    private double prezzo;

    // Costruttore personalizzato per facilitare la creazione
    public Piatto(String nome, String categoria,  double prezzo) {
        this.nome = nome;
        this.categoria = categoria;
        this.prezzo = prezzo;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getCategoria() {
        return categoria;
    }

    public void setCategoria(String categoria) {
        this.categoria = categoria;
    }

    public double getPrezzo() {

        return prezzo;
    }

    public void setPrezzo(double prezzo) {
        this.prezzo = prezzo;
    }

}