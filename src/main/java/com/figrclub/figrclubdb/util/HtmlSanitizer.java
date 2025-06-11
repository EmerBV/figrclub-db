package com.figrclub.figrclubdb.util;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.stereotype.Component;

@Component
public class HtmlSanitizer {
    /**
     * Sanitizes user input to prevent XSS attacks
     * @param input The user input to sanitize
     * @return Sanitized input string
     */
    public String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return Jsoup.clean(input, Safelist.basic());
    }
}
