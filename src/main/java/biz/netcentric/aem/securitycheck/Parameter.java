package biz.netcentric.aem.securitycheck;

import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;

public class Parameter {

    private String name;

    private List<String> values;

    public Parameter(String name, List<String> values) {
        this.name = name;
        this.values = values;
    }

    public Parameter(String name, String... values) {
        this.name = name;
        this.values = Arrays.asList(values);
    }

    public String getName() {
        return name;
    }

    public List<String> getValues() {
        return values;
    }

    public String toExpression() {
        if (values.size() == 1) {
            return String.format("$s=$s", name, values.get(0));
        } else if (values.size() > 1) {
            return String.format("$s=$s", name, StringUtils.joinWith(",", values));
        } else {
            return name;
        }
    }
}
