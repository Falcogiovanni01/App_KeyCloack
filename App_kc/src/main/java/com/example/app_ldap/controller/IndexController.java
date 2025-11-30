package com.example.app_ldap.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.app_ldap.entity.MenuService;
import com.example.app_ldap.entity.Ordine;
import com.example.app_ldap.entity.Piatto;
import com.example.app_ldap.entity.RiepilogoOrdine;
import com.example.app_ldap.repository.OrdineRepository;
import com.example.app_ldap.repository.PiattoRepository;
import com.example.app_ldap.service.LdapRegistrationService;
import com.example.app_ldap.service.XacmlService;

@Controller
public class IndexController {

    @Autowired
    private XacmlService xacmlService;

    @Autowired
    private LdapRegistrationService ldapRegistrationService;

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

    @GetMapping("/login")
    public String showLogin() {
        return "login";
    }

    // REGISTRAZIONE
    @GetMapping("/registrazione")
    public String showRegister() {
        // Cerca il file registrazione.html in templates
        return "registrazione";
    }

    @PostMapping("/registrazione/save")
    public String registerUser(
            @RequestParam String nome,
            @RequestParam String cognome,
            @RequestParam String uid,
            @RequestParam String password) {

        try {
            ldapRegistrationService.registerUser(nome, cognome, uid, password);
            return "redirect:/login?registered=true";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/registrazione?error=true";
        }
    }

    // --- 2. DASHBOARD ---
    @GetMapping("/dashboard")
    public String showDashboard(Authentication auth, Model model) {
        String role = getUserRole(auth);
        if (!xacmlService.evaluate(role, "/dashboard"))
            return "redirect:/login?error=denied";

        if (auth != null) {
            model.addAttribute("username", auth.getName());
            model.addAttribute("role", role);
        }
        return "dashboard";
    }

    // --- 3. PAGINA ORDINI (DINAMICA) ---
    @GetMapping("/ordini")
    public String showOrdina(Authentication auth, Model model) {
        String role = getUserRole(auth);

        // Controllo XACML
        if (!xacmlService.evaluate(role, "/ordini")) {
            return "redirect:/dashboard?error=denied";
        }

        // RECUPERO DATI DA MONGODB
        List<Piatto> primi = piattoRepository.findByCategoria("primo");
        List<Piatto> secondi = piattoRepository.findByCategoria("secondo");

        // Passo i dati all'HTML
        model.addAttribute("listaPrimi", primi);
        model.addAttribute("listaSecondi", secondi);

        return "ordini";
    }

    // --- SALVATAGGIO ORDINE (POST) ---
    @PostMapping("/ordini/save")
    public String saveOrder(
            Authentication auth,
            @RequestParam(name = "piattiId") List<String> piattiId) {

        if (auth == null || !auth.isAuthenticated())
            return "redirect:/login";

        try {
            String username = auth.getName();
            Ordine nuovoOrdine = new Ordine(username, piattiId);
            ordineRepository.save(nuovoOrdine);

            System.out.println(" Ordine salvato per utente: " + username);

            return "redirect:/dashboard?order_success=true";

        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/dashboard?order_error=true";
        }
    }

    // --- 4. GESTIONE ---
    // --- PAGINA GESTIONE (GET) ---
    @GetMapping("/gestione")
    public String showGestisci(Authentication auth, Model model) {
        String role = getUserRole(auth);
        if (!xacmlService.evaluate(role, "/gestione"))
            return "redirect:/dashboard?error=denied";

        // 1. Carica la lista dei piatti attuali
        model.addAttribute("menuAttuale", menuService.getAllPiatti());

        // 2. Carica il riepilogo ordini aggregato
        RiepilogoOrdine riepilogo = menuService.getRiepilogoOrdini();
        model.addAttribute("riepilogoOrdini", riepilogo.getPiattiPerQuantita());
        model.addAttribute("totaleOrdiniUnici", riepilogo.getTotaleOrdiniUnici());

        return "gestione";
    }

    // --- AZIONI ADMIN (POST) ---
    @PostMapping("/gestione/add")
    public String addPiatto(
            @RequestParam String nome,
            @RequestParam String categoria,
            @RequestParam(defaultValue = "0.0") double prezzo) {

        menuService.addPiatto(nome, categoria, prezzo);
        return "redirect:/gestione?add_success=true";
    }

    @PostMapping("/gestione/delete/{id}")
    public String deletePiatto(@PathVariable String id) {
        menuService.deletePiatto(id);
        return "redirect:/gestione?delete_success=true";
    }

    // --- UTILITY ---
    private String getUserRole(Authentication auth) {
        if (auth == null)
            return "GUEST";
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse("ROLE_USER");
    }
}