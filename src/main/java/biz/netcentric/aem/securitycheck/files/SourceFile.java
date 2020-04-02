package biz.netcentric.aem.securitycheck.files;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

@Getter
@Setter
@NoArgsConstructor
public class SourceFile {

    private String content;

    private String location;

    public SourceFile(String content, String location) {
        this.content = content;
        this.location = location;
    }

    public boolean isEmpty() {
        return StringUtils.isBlank(content);
    }

    static SourceFile createEmpty() {
        return new SourceFile(StringUtils.EMPTY, StringUtils.EMPTY);
    }
}
