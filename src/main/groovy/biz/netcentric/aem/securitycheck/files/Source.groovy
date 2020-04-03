package biz.netcentric.aem.securitycheck.files

import org.apache.commons.lang3.StringUtils

class Source {

    String content

    String location

    boolean isEmpty() {
        return StringUtils.isBlank(content)
    }

    static Source createEmpty() {
        return new Source(StringUtils.EMPTY, StringUtils.EMPTY)
    }
}
