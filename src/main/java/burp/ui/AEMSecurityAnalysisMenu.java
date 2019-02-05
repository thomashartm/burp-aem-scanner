package burp.ui;

import burp.BurpExtender;
import burp.BurpHelperDto;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.actions.dispatcher.GetServletExposed;

import javax.swing.*;
import java.awt.event.ActionListener;

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

        register("Dispatcher Path Security checks", new SecurityChecklistAnalysisMenuActionListener(helperDto));
        register("AEM Misconfiguration", new MisconfigurationMenuActionListener(helperDto));
        register("AEM Default Get Servlet checks", new GenericCheckActionListener(helperDto, GetServletExposed.class));
    }

    private void register(final String name, final ActionListener actionListener) {
        final JMenuItem menuItem = new JMenuItem(name);
        menuItem.addActionListener(actionListener);
        this.add(menuItem);
    }
}

