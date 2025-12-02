package com.example.app_ldap.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.app_ldap.entity.Ordine;
import com.example.app_ldap.entity.Piatto;
import com.example.app_ldap.entity.RiepilogoOrdine;
import com.example.app_ldap.repository.OrdineRepository;
import com.example.app_ldap.repository.PiattoRepository;
import com.example.app_ldap.service.MenuService;
import com.example.app_ldap.service.XacmlService;

@Controller
public class IndexController {

    @Autowired
    private XacmlService xacmlService;

    @Autowired
    private PiattoRepository piattoRepository;

    @Autowired
    private OrdineRepository ordineRepository;

    @Autowired
    private MenuService menuService;

    // --- 1. HOME & LOGIN ---

    @GetMapping("/")
    public String home() {
        return "redirect:/home";
    }

    @GetMapping("/home")
    public String showHomePage() {

        return "home";
    }

    // NOTA: Con Keycloak, la pagina di login è esterna.
    // Spring intercetta "/login" e manda l'utente su Keycloak automaticamente.
    // Non serve più un metodo showLogin() qui se usi oauth2Login() standard.

    // --- 2. DASHBOARD ---
    @GetMapping("/dashboard")
    public String showDashboard(Authentication auth, Model model) {
        System.out.println("---- DASHBOARD ACCESS:" + auth.toString());
        String role = getUserRole(auth);

        // Controllo XACML (Autorizzazione basata su attributi/ruoli)
        if (!xacmlService.evaluate(role, "/dashboard"))
            return "redirect:/?error=denied";

        if (auth != null) {
            // Recupera il nome utente dal token OIDC (Keycloak)
            String username = auth.getName();
            if (auth.getPrincipal() instanceof OidcUser oidcUser) {
                username = oidcUser.getPreferredUsername();
            }

            model.addAttribute("username", username);
            model.addAttribute("role", role);
        }
        return "dashboard";
    }

    // --- 3. PAGINA ORDINI (User & Admin) ---

    @GetMapping("/ordini")
    public String showOrdina(Authentication auth, Model model) {
        String role = getUserRole(auth);

        // Controllo XACML
        if (!xacmlService.evaluate(role, "/ordini")) {
            return "redirect:/dashboard?error=denied";
        }

        // Recupero Dati da MongoDB
        List<Piatto> primi = piattoRepository.findByCategoria("primo");
        List<Piatto> secondi = piattoRepository.findByCategoria("secondo");

        model.addAttribute("listaPrimi", primi);
        model.addAttribute("listaSecondi", secondi);

        return "ordini";
    }

    @PostMapping("/ordini/save")
    public String saveOrder(
            Authentication auth,
            @RequestParam(name = "piattiId") List<String> piattiId) {

        if (auth == null || !auth.isAuthenticated())
            return "redirect:/";

        try {
            String username = auth.getName();
            if (auth.getPrincipal() instanceof OidcUser oidcUser) {
                username = oidcUser.getPreferredUsername();
            }

            Ordine nuovoOrdine = new Ordine(username, piattiId);
            ordineRepository.save(nuovoOrdine);

            System.out.println(" Ordine salvato per utente: " + username);

            return "redirect:/dashboard?order_success=true";

        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/dashboard?order_error=true";
        }
    }

    // --- 4. GESTIONE (Solo Admin) ---

    @GetMapping("/gestione")
    public String showGestisci(Authentication auth, Model model) {
        String role = getUserRole(auth);

        // Controllo XACML
        if (!xacmlService.evaluate(role, "/gestione"))
            return "redirect:/dashboard?error=denied";

        model.addAttribute("menuAttuale", menuService.getAllPiatti());

        RiepilogoOrdine riepilogo = menuService.getRiepilogoOrdini();
        model.addAttribute("riepilogoOrdini", riepilogo.getPiattiPerQuantita());
        model.addAttribute("totaleOrdiniUnici", riepilogo.getTotaleOrdiniUnici());

        return "gestione";
    }

    @PostMapping("/gestione/add")
    public String addPiatto(
            @RequestParam String nome,
            @RequestParam String categoria,
            @RequestParam(defaultValue = "0.0") double prezzo) {

        menuService.addPiatto(nome, categoria, prezzo);
        return "redirect:/gestisci?add_success=true";
    }

    @PostMapping("/gestione/delete/{id}")
    public String deletePiatto(@PathVariable String id) {
        menuService.deletePiatto(id);
        return "redirect:/gestione?delete_success=true";
    }

    // --- UTILITY ---
    // Estrae il ruolo dal token OAuth2/OIDC mappato in SecurityConfig
    // private String getUserRole(Authentication auth) {
    // if (auth == null)
    // return "GUEST";
    // return auth.getAuthorities().stream()
    // .map(GrantedAuthority::getAuthority)
    // .filter(a -> a.startsWith("ROLE_"))
    // .findFirst()
    // .orElse("ROLE_USER");
    // }
    private String getUserRole(Authentication auth) {
        if (auth == null) {
            return "GUEST";
        }

        // Se hai ADMIN, dai priorità ad ADMIN
        boolean isAdmin = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(a -> a.equals("ROLE_ADMIN"));

        if (isAdmin) {
            return "ROLE_ADMIN";
        }

        // Altrimenti, se hai USER, usa USER
        boolean isUser = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(a -> a.equals("ROLE_USER"));

        if (isUser) {
            return "ROLE_USER";
        }

        // Tutto il resto (default-roles, offline_access, ecc.) lo ignori
        return "GUEST";
    }

}