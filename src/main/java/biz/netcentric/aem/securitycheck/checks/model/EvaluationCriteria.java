package biz.netcentric.aem.securitycheck.checks.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class EvaluationCriteria {

    private RuleEvaluationType ruleEvaluationType;

    private List<EvaluationRule> evaluationRules;

    EvaluationCriteria(){
        this.evaluationRules = new ArrayList<>();
    }

    public void addBodyContainsAnyRule(String... tokens){
        this.evaluationRules.add(BodyContainsRule.containsAny(tokens));
    }

    public void addBodyContainsAllRule(String... tokens){
        this.evaluationRules.add(BodyContainsRule.containsAll(tokens));
    }
    /*
    detect:
            - type: all
    expectedStatusCode: 200
    bodyContains:
            - "CRX"
            - "Explorer"
    * */
}
