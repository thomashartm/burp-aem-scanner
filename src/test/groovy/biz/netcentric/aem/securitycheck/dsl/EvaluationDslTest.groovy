package biz.netcentric.aem.securitycheck.dsl

import org.junit.Assert
import org.junit.jupiter.api.Test

class EvaluationDslTest {

    @Test
    void all() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                messageBody: "{results: [xxx:yyy], total: 1}", statusCode: 200)

        EvaluationDsl dsl = new EvaluationDsl(responseEntity)

        dsl.all {
            expect body contains "results"
            expect status is 200
        }

        Assert.assertTrue dsl.allCondition()
    }

    @Test
    void allFailsWhenOneExpectationDoesNotMatch() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                messageBody: "{results: [xxx:yyy], total: 1}", statusCode: 200, mimeType: "application/json")

        EvaluationDsl dsl = new EvaluationDsl(responseEntity)

        dsl.all {
            expect body contains "results"
            expect status is 200
            expect mimeType is "text/html"
        }

        Assert.assertFalse dsl.allCondition()
    }


    @Test
    void oneOf() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                messageBody: "{results: [xxx:yyy], total: 1}", statusCode: 200, mimeType: "application/json")

        EvaluationDsl dsl = new EvaluationDsl(responseEntity)

        dsl.oneOf {
            expect body contains "text"
            expect status is 200
            expect mimeType is "text/html"
        }

        Assert.assertTrue dsl.oneOfCondition()
    }

    @Test
    void oneOfFailsEmpty() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                messageBody: "{results: [xxx:yyy], total: 1}", statusCode: 200, mimeType: "application/json")

        EvaluationDsl dsl = new EvaluationDsl(responseEntity)

        dsl.oneOf {
        }

        Assert.assertFalse dsl.oneOfCondition()
    }

    @Test
    void oneOfFailsWhenNoConditionMatches() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                messageBody: "error", statusCode: 404, mimeType: "application/text")

        EvaluationDsl dsl = new EvaluationDsl(responseEntity)

        dsl.oneOf {
            expect body contains "results"
            expect status is 200
            expect mimeType is "application/json"
        }

        Assert.assertFalse dsl.oneOfCondition()
    }
}
