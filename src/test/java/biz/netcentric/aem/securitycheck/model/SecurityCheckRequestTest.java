package biz.netcentric.aem.securitycheck.model;

import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

class SecurityCheckRequestTest {

    private static final String[] PATHS = {"/content/weretail", "/content/geomoetrixx/en", "/content/de/products"};

    private static final String[] SELECTORS = {"1", "infinity"};

    private static final String[] EXTENSIONS = {"", "html", "json"};

    private SecurityCheckRequest securityCheckRequest;

    @BeforeEach
    void setUp() {
        this.securityCheckRequest = new SecurityCheckRequest();
        this.securityCheckRequest.setPaths(Arrays.asList(PATHS));
        this.securityCheckRequest.setSelectors(Arrays.asList(SELECTORS));
        this.securityCheckRequest.setExtensions(Arrays.asList(EXTENSIONS));
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void createPathMutations() {
        List<String> mutations = this.securityCheckRequest.createPathMutations();

        Assert.assertTrue(mutations.containsAll(Arrays.asList(
                "/content/weretail",
                "/content/geomoetrixx/en",
                "/content/de/products",
                "/content/weretail.1",
                "/content/geomoetrixx/en.1",
                "/content/de/products.1",
                "/content/weretail.infinity",
                "/content/geomoetrixx/en.infinity",
                "/content/de/products.infinity",
                "/content/weretail.1.html",
                "/content/geomoetrixx/en.1.html",
                "/content/de/products.1.html",
                "/content/weretail.infinity.html",
                "/content/geomoetrixx/en.infinity.html",
                "/content/de/products.infinity.html")
        ));

        Assert.assertEquals(36, mutations.size());
    }
}