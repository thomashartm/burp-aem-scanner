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
        final JMenuItem pathBasedCheckItem = new JMenuItem("Dispatcher Path Security checks");
        pathBasedCheckItem.addActionListener(new SecurityChecklistAnalysisMenuActionListener(helperDto));
        this.add(pathBasedCheckItem);

        final JMenuItem misconfigItem = new JMenuItem("AEM Misconfiguration");
        misconfigItem.addActionListener(new MisconfigurationMenuActionListener(helperDto));
        this.add(misconfigItem);
    }
}

