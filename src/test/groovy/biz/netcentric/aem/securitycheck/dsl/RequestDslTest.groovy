package biz.netcentric.aem.securitycheck.dsl

import org.junit.jupiter.api.Test
import static biz.netcentric.aem.securitycheck.dsl.EvaluationDsl.*

class RequestDslTest {

    @Test
    void evaluate() {

        RequestDsl requestDsl = new RequestDsl()

        requestDsl.evaluate {
            expect "xxx" contains "results"
        }
    }
}