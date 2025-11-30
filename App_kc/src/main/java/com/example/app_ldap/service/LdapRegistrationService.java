package com.example.app_ldap.service;

import javax.naming.Name;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LdapRegistrationService {

    @Autowired
    private LdapTemplate ldapTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder; 

    public void registerUser(String nome, String cognome, String uid, String password) {
        
        // Cripta la password usando BCrypt prima di salvarla
        String encodedPassword = passwordEncoder.encode(password);


        // 1. Creiamo il DN (Distinguished Name) dell'utente
        // Esempio: cn=Nome Cognome,ou=people,dc=mensa,dc=com
        Name userDn = LdapNameBuilder.newInstance()
                .add("ou", "people")
                .add("cn", nome + " " + cognome)
                .build();

        // 2. Prepariamo gli attributi dell'utente
        DirContextAdapter context = new DirContextAdapter(userDn);

        // Classi obbligatorie per un utente LDAP standard
        context.setAttributeValues("objectClass", new String[] {
                "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson",
                "posixAccount"
        });

        context.setAttributeValue("cn", nome + " " + cognome);
        context.setAttributeValue("sn", cognome);
        context.setAttributeValue("uid", uid); // Username per il login
        context.setAttributeValue("userPassword", encodedPassword); // In chiaro per semplicità

        // Attributi Posix obbligatori (generiamo numeri casuali per semplicità)
        int randomUid = 1000 + (int) (Math.random() * 9000);
        context.setAttributeValue("uidNumber", String.valueOf(randomUid));
        context.setAttributeValue("gidNumber", "501"); // 501 è il GID del gruppo 'user' creato
        context.setAttributeValue("homeDirectory", "/home/users/" + uid);
        context.setAttributeValue("loginShell", "/bin/bash");

        // 3. Salviamo l'utente in LDAP (Crea la persona)
        ldapTemplate.bind(context);
        System.out.println(" Utente " + uid + " creato in ou=people");

        // 4. Aggiungiamo l'utente al gruppo 'user' (Role Assignment)
        addUserToGroup(uid);
    }

    private void addUserToGroup(String uid) {
        // Cerchiamo il gruppo 'user' in ou=group
        Name groupDn = LdapNameBuilder.newInstance()
                .add("ou", "group")
                .add("cn", "user") 
                .build();

        DirContextOperations ctx = ldapTemplate.lookupContext(groupDn);
        ctx.addAttributeValue("memberUid", uid);

        ldapTemplate.modifyAttributes(ctx);
        System.out.println(" Utente " + uid + " aggiunto al gruppo 'user'");
    }
}