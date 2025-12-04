package com.example.app_ldap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
public class EnvironmentDebug {

    @Autowired
    private Environment env;

    @PostConstruct
    public void printEnvVars() {

        System.out.println("=========== ENV DEBUG START ===========");

        String[] keys = new String[] {
                "VAULT_TOKEN",
                "MONGO_ROOT_PASSWORD",
                "KEYCLOACK_PASSWORD",
                "KEYCLOACK_CLIENT_SECRET" // <-- NOME CORRETTO!
        };

        for (String key : keys) {
            String value = env.getProperty(key);

            if (value == null) {
                System.out.println(key + " = NULL");
            } else {
                System.out.println(key + " = LENGTH(" + value.length() + ")");
            }
        }

        System.out.println("=========== ENV DEBUG END =============");
    }
}
