package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.dsl.detection.EvaluationRuleDsl
import biz.netcentric.aem.securitycheck.http.ResponseEntity
import biz.netcentric.aem.securitycheck.model.EvaluationResult


/**
 * DSL to process the define and process the evaluation criteria for responses
 *
 * It can be used to evaluate either and/or condition chained expectations
 * {@code
 * {
 *  all {
 *      expect body contains "results"
 *      expect statusCode is 200
 *      expect responseType equals "text/html"
 *  }
 *
 *  oneOf {
 *      expect body contains "prompt("
 *      expect body equals "<img src=x onerror=alert(1)>"
 *  }
 * }
 * }
 *
 */
class EvaluationDsl {

    ResponseEntity response

    List<EvaluationResult> allGroup = []

    List<EvaluationResult> oneOfGroup = []

    EvaluationDsl(ResponseEntity response) {
        this.response = response
    }

    def all(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = EvaluationRuleDsl) Closure closure) {
        List<EvaluationResult> results = executeEvaluationClosure(closure)
        this.allGroup.addAll(results)
    }

    def oneOf(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = EvaluationRuleDsl) Closure closure) {
        List<EvaluationResult> results = executeEvaluationClosure(closure)
        this.oneOfGroup.addAll(results)
    }

    private List<EvaluationResult> executeEvaluationClosure(Closure closure) {
        EvaluationRuleDsl rule = new EvaluationRuleDsl(this.response)
        closure.setDelegate(rule)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)

        closure()

        List<EvaluationResult> results = closure.getResult()

        results
    }

    boolean allCondition(){
        int matches = 0
        getAllGroup().each {result ->
            if(result.isMatch()){
                matches++
            }
        }

        return getAllGroup().size() == matches
    }

    boolean oneOfCondition(){
        int matches = 0
        getOneOfGroup().each {result ->
            if(result.isMatch()){
                matches++
            }
        }

        return matches > 0
    }
}