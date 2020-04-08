package biz.netcentric.aem.securitycheck.dsl

import org.junit.jupiter.api.Test

class EvaluationDslTest {

    @Test
    void all() {
        EvaluationDsl dsl = new EvaluationDsl()
        dsl.all {

        }

        // TODO expect that all rules are evaluated
    }

    @Test
    void oneOf() {
    }
}
