package com.example.app_ldap.service;

import com.example.app_ldap.entity.Piatto;
import com.example.app_ldap.repository.PiattoRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class MongoDataSeeder implements CommandLineRunner {

    private final PiattoRepository piattoRepository;

    public MongoDataSeeder(PiattoRepository piattoRepository) {
        this.piattoRepository = piattoRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        // Controlla se ci sono piatti nel DB. Se ce ne sono, non fa nulla.
        if (piattoRepository.count() == 0) {
            System.out.println("  Il Menu è vuoto! Aggiungo piatti di default...");
            
            // Crea gli oggetti Piatto (Nota: calorie impostate a 0 come richiesto)
            Piatto p1 = new Piatto("Spaghetti alla Carbonara", "primo",  5.00);
            Piatto p2 = new Piatto("Risotto ai Funghi", "primo",  6.50);
            Piatto p3 = new Piatto("Pasta al Pomodoro", "primo",  4.00);
            
            Piatto s1 = new Piatto("Cotoletta alla Milanese", "secondo", 8.00);
            Piatto s2 = new Piatto("Filetto di Salmone", "secondo",  12.00);
            Piatto s3 = new Piatto("Mozzarella Caprese", "secondo",  7.00);

            List<Piatto> piattiDefault = Arrays.asList(p1, p2, p3, s1, s2, s3);
            
            // Salva tutti i piatti su MongoDB
            piattoRepository.saveAll(piattiDefault);
            
            System.out.println(" Menu del giorno caricato con successo! (Totale: " + piattiDefault.size() + " piatti)");
        } else {
             System.out.println(" Menu già popolato. Nessun seeding necessario.");
        }
    }
}