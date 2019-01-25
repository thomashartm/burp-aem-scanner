package burp.ui;

import burp.*;

import javax.swing.*;

/**
 * Triggers the dispatcher analysis event which starts Dispatcher checklist evaluations a hiost
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class AEMSecurityAnalysisMenu extends JMenu {

    private BurpExtender extender;

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    public AEMSecurityAnalysisMenu(final BurpHelperDto helperDto) {

        this.setText("AEM Actions");

        final JMenuItem headerItem = new JMenuItem("Path based security checks");
        headerItem.addActionListener(new SecurityChecklistAnalysisMenuActionListener(helperDto));

        this.add(headerItem);
    }
}

