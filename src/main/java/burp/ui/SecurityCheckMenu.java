package burp.ui;

import biz.netcentric.aem.securitycheck.SecurityCheckService;
import burp.data.BurpHelperDto;

import javax.swing.*;
import java.awt.event.ActionListener;

public class SecurityCheckMenu extends JMenu {

    private final BurpHelperDto helperDto;

    public SecurityCheckMenu(final SecurityCheckService securityCheckService, final BurpHelperDto helperDto) {
        this.helperDto = helperDto;
        this.setText("AEM Checks");
        // CRX
        register("Run all checks", new GenericCheckActionListener(securityCheckService, helperDto));
    }

    private void register(final String name, final ActionListener actionListener) {
        final JMenuItem menuItem = new JMenuItem(name);
        menuItem.addActionListener(actionListener);
        this.add(menuItem);
    }

    private void addMenuSeparator() {
        this.addSeparator();
    }
}


