package burp.ui;

import burp.BurpExtender;
import burp.BurpHelperDto;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.actions.SecurityCheckExecutorService;
import burp.actions.accesscontrol.DefaultLoginWithLoginPagePossible;
import burp.actions.accesscontrol.WriteAccessPossible;
import burp.actions.crx.CrxExposedDetector;
import burp.actions.dispatcher.*;
import burp.actions.misconfiguration.AuditServletDetector;
import burp.actions.misconfiguration.DebugFilterDetector;
import burp.actions.misconfiguration.WcmSuggestionServletDetector;
import burp.actions.xss.FlippingTypeWithChildrenlistSelector;

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

        // CRX
        register("CRX Exposed Check", new GenericCheckActionListener(executorService, helperDto, CrxExposedDetector.class));
        addMenuSeparator();

        // Login and permissions related misconfiguration
        register("Login with DefaultCredentials", new GenericCheckActionListener(executorService, helperDto, DefaultLoginWithLoginPagePossible.class));
        register("AEM WriteAccessCheck", new GenericCheckActionListener(executorService, helperDto, WriteAccessPossible.class));
        addMenuSeparator();

        // Dispatcher
        register("DefaultGetServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, GetServletExposed.class));
        register("QueryBuilder Exposed Check", new GenericCheckActionListener(executorService, helperDto, QueryBuilderExposed.class));
        register("GQLQueryServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, GQLServletExposed.class));
        register("PostServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, PostServletExposed.class));
        addMenuSeparator();

        // XSS
        register("XSS in AEM SWFs Check", new GenericCheckActionListener(executorService, helperDto, XSSinSWFDetector.class));
        register("XSS in childlist selector", new GenericCheckActionListener(executorService, helperDto, FlippingTypeWithChildrenlistSelector.class));
        addMenuSeparator();

        register("Felix Web Console Check", new GenericCheckActionListener(executorService, helperDto, LoginStatusServletExposed.class));
        register("Felix LoginStatusServlet Exposed Check", new GenericCheckActionListener(executorService, helperDto, LoginStatusServletExposed.class));
        addMenuSeparator();

        // Various AEM Misconfiguration
        register("WCMDebugFilter enabled", new GenericCheckActionListener(executorService, helperDto, DebugFilterDetector.class));
        register("WCMSuggestionsServlet enabled", new GenericCheckActionListener(executorService, helperDto, WcmSuggestionServletDetector.class));
        register("AuditLogServlet enabled", new GenericCheckActionListener(executorService, helperDto, AuditServletDetector.class));
    }

    private void register(final String name, final ActionListener actionListener) {
        final JMenuItem menuItem = new JMenuItem(name);
        menuItem.addActionListener(actionListener);
        this.add(menuItem);
    }

    private void addMenuSeparator(){
        this.addSeparator();
    }
}

