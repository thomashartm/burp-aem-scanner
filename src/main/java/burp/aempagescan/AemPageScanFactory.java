package burp.aempagescan;

import burp.IBurpExtenderCallbacks;
import burp.aempagescan.impl.DebugParamScan;
import burp.aempagescan.impl.PageMetaDataGrappingScan;

import java.util.ArrayList;
import java.util.List;

/**
 * Manages the instantiation of typed active AEM scanner checks via a static factory method.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class AemPageScanFactory {

    public static List<ActiveAemPageScan> createAEMPageScanners(final IBurpExtenderCallbacks callbacks){
        final List<ActiveAemPageScan> scans = new ArrayList<>();

        scans.add(new DebugParamScan(callbacks));
        scans.add(new PageMetaDataGrappingScan(callbacks));

        return scans;
    }
}
