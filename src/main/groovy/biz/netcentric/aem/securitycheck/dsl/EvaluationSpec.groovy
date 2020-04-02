package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.checks.model.EvaluationCriteria
import biz.netcentric.aem.securitycheck.checks.model.RuleEvaluationType

class EvaluationSpec {

    EvaluationCriteria evaluationCriteria;

    EvaluationSpec() {
        this.evaluationCriteria = new EvaluationCriteria()
    }

    void matches(RuleEvaluationType evaluationType) {
        this.evaluationCriteria.setRuleEvaluationType(evaluationType)
    }

    void bodyContainsAny(String... tokens) {
        this.evaluationCriteria.add
    }

    void bodyContainsAll(String... tokens) {

    }

}