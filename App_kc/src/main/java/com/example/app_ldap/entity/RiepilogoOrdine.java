package com.example.app_ldap.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.Map;

/**
 * Data Transfer Object (DTO) per la visualizzazione aggregata degli ordini nella pagina Admin.
 * Contiene i conteggi totali dei piatti da preparare.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RiepilogoOrdine {
    
    // Mappa dove la chiave è il Nome del Piatto e il valore è la Quantità totale ordinata.
    // Esempio: {"Carbonara": 20, "Cotoletta": 15}
    private Map<String, Long> piattiPerQuantita;
    
    // Conteggio totale degli ordini unici inviati.
    private long totaleOrdiniUnici;
}
