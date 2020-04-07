package biz.netcentric.aem.securitycheck.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Getter
@Setter
@NoArgsConstructor
public class SecurityCheckRequest{

    private static final String PATH_WITH_EXT = "%s.%s";

    private String method;

    private String referrer;

    private List<String> requestHeader;

    private List<String> paths;

    private List<String> selectors;

    private List<String> extensions;

    private EvaluationCriteria evaluationCriteria;

    public List<String> createPathMutations() {
        List<String> mutations = joinPathsAndSuffixes(paths, selectors);
        return joinPathsAndSuffixes(mutations, extensions);
    }

    private List<String> joinPathsAndSuffixes(List<String> paths, List<String> suffixes){
        List<String> mutations = new ArrayList<>();
        paths.forEach(path -> {
            // plain and empty copy bevore adding any mutations
            mutations.add(path);
            suffixes.forEach(suffix -> {
                // joins them using a dot as long as the suffix is not empty.
                if(StringUtils.isNotBlank(suffix)) {
                    mutations.add(String.format(PATH_WITH_EXT, path, suffix));
                }else{
                    //If empty then just add the path
                    mutations.add(path);
                }
            });
        });

        return mutations;
    }

    public HttpMethod method(){
        Optional<HttpMethod> selectedMethod = Arrays.asList(HttpMethod.values())
                .stream()
                .filter(httpMethod -> StringUtils.equalsIgnoreCase(httpMethod.getName(), this.method)).findFirst();

        return selectedMethod.orElseThrow();
    }

    /*
    - name: "GET /crx/de"
    method: "GET"
    paths:
            - "/crx/de"
            - "/crx/de/index.jsp"
    extensions:
            - ".json"
    requestHeaders:
    host: "example.com"
    Referer: "referer.example.com"
    authenticationHeaders:
    authentication: "Basic xyz"
    params:
    param1: "value1"
    param2: "value2"
    detect:
            - type: all
    expectedStatusCode: 200
    bodyContains:
            - "CRX"
            - "Explorer"

     */
}
