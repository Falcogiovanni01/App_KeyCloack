package com.example.app_ldap.service;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

@Service
public class XacmlService {

    /**
     * Valuta se l'utente ha il permesso leggendo policy.xml
     */
    public boolean evaluate(String userRole, String resourceRequested) {
        try {
            // 1. Carica il file policy.xml dalle risorse
            InputStream is = getClass().getResourceAsStream("/policy.xml");
            
            if (is == null) {
                System.err.println(" ERRORE: File policy.xml non trovato in src/main/resources!");
                return false; 
            }

            // 2. Legge l'XML
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(is);
            doc.getDocumentElement().normalize();

            // 3. Controlla tutte le regole
            NodeList rules = doc.getElementsByTagName("Rule");

            for (int i = 0; i < rules.getLength(); i++) {
                Element rule = (Element) rules.item(i);
                String effect = rule.getAttribute("Effect"); // Permit o Deny

                // Legge i tag interni
                String ruleResource = getTagValue(rule, "Resource");
                String ruleRole = getTagValue(rule, "AttributeValue");

                // 4. Confronto
                if (resourceRequested.equals(ruleResource)) {
                    if (userRole.equals(ruleRole)) {
                        return "Permit".equals(effect);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        
        return false; // Nessuna regola trovata -> Negato
    }

    private String getTagValue(Element element, String tagName) {
        NodeList nodeList = element.getElementsByTagName(tagName);
        if (nodeList != null && nodeList.getLength() > 0) {
            return nodeList.item(0).getTextContent();
        }
        return "";
    }
}