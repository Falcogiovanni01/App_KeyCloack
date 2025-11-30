package com.example.app_ldap.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "ordini") // Collezione Ordini su MongoDB
public class Ordine {

    @Id
    private String id;

    // Chi ha effettuato l'ordine (legato all'utente LDAP)
    private String username; 

    // Lista degli ID dei piatti ordinati
    private List<String> piattiId; 
    
    // Timestamp dell'ordine
    private LocalDateTime dataOrdine;
    
    // Stato per la cucina
    private String stato; // "Inviato", "In preparazione", "Pronto"

    // Costruttore per la creazione dell'ordine
    public Ordine(String username, List<String> piattiId) {
        this.username = username;
        this.piattiId = piattiId;
        this.dataOrdine = LocalDateTime.now();
        this.stato = "Inviato";
    }
} 
