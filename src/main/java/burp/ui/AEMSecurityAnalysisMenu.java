package burp.ui;

import burp.BurpExtender;
import burp.BurpHelperDto;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.actions.SecurityCheckExecutorService;
import burp.actions.accesscontrol.WriteAccessPossible;
import burp.actions.crx.CrxExposedDetector;
import burp.actions.dispatcher.*;
import burp.actions.misconfiguration.AuditServletDetector;
import burp.actions.misconfiguration.DebugFilterDetector;
import burp.actions.misconfiguration.WcmSuggestionServletDetector;

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

    public AEMSecurityAnalysisMenu(final SecurityCheckExecutorService executorService, final BurpHelperDto helperDto) {
        this.setText("AEM Actions");

        register("DefaultGetServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, GetServletExposed.class));
        register("QueryBuilder Exposed Check", new GenericCheckActionListener(executorService, helperDto, QueryBuilderExposed.class));
        register("GQLQueryServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, GQLServletExposed.class));
        register("PostServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, PostServletExposed.class));
        register("LoginStatusServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, LoginStatusServletExposed.class));
        register("FelixConsole Check", new GenericCheckActionListener(executorService, helperDto, LoginStatusServletExposed.class));

        // CRX
        register("CRX Exposed Check", new GenericCheckActionListener(executorService, helperDto, CrxExposedDetector.class));

        // permissions related misconfiguration
        register("AEM WriteAccessCheck", new GenericCheckActionListener(executorService, helperDto, WriteAccessPossible.class));

        // AEM Misconfiguration
        register("WCMDebugFilter enabled", new GenericCheckActionListener(executorService, helperDto, DebugFilterDetector.class));
        register("WCMSuggestionsServlet enabled", new GenericCheckActionListener(executorService, helperDto, WcmSuggestionServletDetector.class));
        register("AuditLogServlet enabled", new GenericCheckActionListener(executorService, helperDto, AuditServletDetector.class));
    }

    private void register(final String name, final ActionListener actionListener) {
        final JMenuItem menuItem = new JMenuItem(name);
        menuItem.addActionListener(actionListener);
        this.add(menuItem);
    }
}

