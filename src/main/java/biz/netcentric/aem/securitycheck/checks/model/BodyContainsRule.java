package biz.netcentric.aem.securitycheck.checks.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Arrays;
import java.util.List;

@Getter
@Setter
public class BodyContainsRule implements EvaluationRule {

    private final List<String> tokens;

    private boolean all;

    public BodyContainsRule(boolean all, String... tokens) {
        this.all = all;
        this.tokens = Arrays.asList(tokens);
    }

    public static BodyContainsRule containsAll(String... tokens){
        return new BodyContainsRule(true, tokens);
    }

    public static BodyContainsRule containsAny(String... tokens){
        return new BodyContainsRule(false, tokens);
    }
}
