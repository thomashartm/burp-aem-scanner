package burp.ui;

import burp.BurpExtender;
import burp.BurpHelperDto;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.actions.accesscontrol.WriteAccessPossible;
import burp.actions.dispatcher.GQLServletExposed;
import burp.actions.dispatcher.GetServletExposed;
import burp.actions.dispatcher.PostServletExposed;
import burp.actions.dispatcher.QueryBuilderExposed;

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

        register("AEM DefaultGetServlet Exposed Check", new GenericCheckActionListener(helperDto, GetServletExposed.class));
        register("AEM QueryBuilder Exposed Check", new GenericCheckActionListener(helperDto, QueryBuilderExposed.class));
        register("AEM GQLQueryServlet Exposed Check", new GenericCheckActionListener(helperDto, GQLServletExposed.class));
        register("AEM PostServlet Exposed Check", new GenericCheckActionListener(helperDto, PostServletExposed.class));

        // permissions related misconfiguration
        register("AEM WriteAccessCheck", new GenericCheckActionListener(helperDto, WriteAccessPossible.class));
    }

    private void register(final String name, final ActionListener actionListener) {
        final JMenuItem menuItem = new JMenuItem(name);
        menuItem.addActionListener(actionListener);
        this.add(menuItem);
    }
}

