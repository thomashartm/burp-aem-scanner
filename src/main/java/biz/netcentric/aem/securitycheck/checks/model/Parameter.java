package biz.netcentric.aem.securitycheck.checks.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@Accessors(fluent = true)
public class Parameter {

    private String name;

    private List<String> values;

}
