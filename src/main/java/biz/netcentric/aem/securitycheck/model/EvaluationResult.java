package biz.netcentric.aem.securitycheck.model;

import lombok.Builder;
import lombok.Getter;

import java.net.URI;


@Getter
@Builder
public class EvaluationResult {

    String checkId;

    URI url;

    String name;

    boolean result;

    boolean mandatory;
}
