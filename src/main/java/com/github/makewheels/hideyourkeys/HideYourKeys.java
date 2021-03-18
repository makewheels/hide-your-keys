package com.github.makewheels.hideyourkeys;

public class HideYourKeys {
    /**
     * Spring Boot
     * Support application.properties file only
     */
    public static void hideKeysInSpringBoot() {
        SecretKeyUtil.overrideKeys();
    }

}
