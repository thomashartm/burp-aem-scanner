package biz.netcentric.aem.securitycheck.dsl;

import biz.netcentric.aem.securitycheck.DslParser;
import biz.netcentric.aem.securitycheck.model.SecurityCheck;
import biz.netcentric.aem.securitycheck.model.SecurityCheckRequest;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

class DslParserTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void loadScripts() {
        DslParser dslParser = new DslParser();
        List<SecurityCheck> securityChecks = dslParser.loadScripts("/securitychecks");

        Assert.assertEquals(1, securityChecks.size());
    }

    @Test
    void verifySecurityCheckMetadata() {
        DslParser dslParser = new DslParser();
        List<SecurityCheck> securityChecks = dslParser.loadScripts("/securitychecks");

        SecurityCheck check = securityChecks.get(0);
        Assert.assertEquals("CRX Test", check.getId());
        Assert.assertTrue(check.getCategories().containsAll(Arrays.asList("xss", "ssrf", "xxe")));
    }

    @Test
    void verifySecurityCheckRequestSteps() {
        DslParser dslParser = new DslParser();
        List<SecurityCheck> securityChecks = dslParser.loadScripts("/securitychecks");

        SecurityCheck check = securityChecks.get(0);
        List<SecurityCheckRequest> steps = check.getRequestSteps();

        Assert.assertTrue(steps.get(0).getPaths().containsAll(Arrays.asList("/content", "/etc", "/apps")));

        Assert.assertTrue(steps.get(1).getPaths().containsAll(Arrays.asList("/content", "/etc", "/apps")));
    }

    @Test
    void verifyEmptyPath() {
        DslParser dslParser = new DslParser();
        List<SecurityCheck> securityChecks = dslParser.loadScripts("/securitychecksnonexist");

        Assert.assertEquals(0, securityChecks.size());
    }
}