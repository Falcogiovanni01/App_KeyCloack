package com.example.app_ldap.service;

import com.example.app_ldap.entity.*;
import com.example.app_ldap.repository.OrdineRepository;
import com.example.app_ldap.repository.PiattoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class MenuService {

    @Autowired
    private PiattoRepository piattoRepository;
    
    @Autowired
    private OrdineRepository ordineRepository;

    /**
     * Aggiunge un nuovo piatto al database MongoDB.
     * @param nome Nome del piatto
     * @param categoria Categoria ("primo" o "secondo")
     * @param prezzo Prezzo del piatto
     */
    public Piatto addPiatto(String nome, String categoria, double prezzo) {
        // Le calorie sono state rimosse come richiesto
        Piatto nuovoPiatto = new Piatto(nome, categoria, prezzo); 
        return piattoRepository.save(nuovoPiatto);
    }

    /**
     * Rimuove un piatto dal database.
     * @param id ID del piatto da rimuovere
     */
    public void deletePiatto(String id) {
        piattoRepository.deleteById(id);
    }

    /**
     * Aggrega tutti gli ordini ricevuti e crea un riepilogo per la cucina.
     * @return DTO RiepilogoOrdine contenente i conteggi totali
     */
    public RiepilogoOrdine getRiepilogoOrdini() {
        // 1. Recupera TUTTI gli ordini e TUTTI i piatti
        List<Ordine> tuttiGliOrdini = ordineRepository.findAll();
        List<Piatto> tuttiIPiatti = piattoRepository.findAll();
        
        // Mappa ID Piatto -> Nome Piatto (utile per la visualizzazione)
        Map<String, String> idToNameMap = tuttiIPiatti.stream()
                .collect(Collectors.toMap(Piatto::getId, Piatto::getNome));

        // 2. Aggrega la lista degli ID di tutti i piatti ordinati
        List<String> tuttiGliIdOrdinati = tuttiGliOrdini.stream()
                .flatMap(ordine -> ordine.getPiattiId().stream())
                .collect(Collectors.toList());

        // 3. Conta la frequenza di ogni ID e mappala al Nome
        Map<String, Long> piattiAggregati = tuttiGliIdOrdinati.stream()
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()))
                .entrySet().stream()
                .collect(Collectors.toMap(
                        entry -> idToNameMap.getOrDefault(entry.getKey(), "Sconosciuto"), // Mappa ID a Nome
                        Map.Entry::getValue // Conserva il conteggio
                ));
        
        // 4. Totale ordini unici (quante persone hanno ordinato)
        long totaleOrdiniUnici = tuttiGliOrdini.size();

        return new RiepilogoOrdine(piattiAggregati, totaleOrdiniUnici);
    }
    
    /**
     * Ottiene tutti i piatti attivi nel menu.
     */
    public List<Piatto> getAllPiatti() {
        return piattoRepository.findAll();
    }
}