package biz.netcentric.aem.securitycheck.dsl

import org.junit.jupiter.api.Test

class RequestDslTest {

    @Test
    void evaluate() {

        RequestDsl requestDsl = new RequestDsl()

        requestDsl.evaluate {
            expect "xxx" contains "results"
        }
    }
}