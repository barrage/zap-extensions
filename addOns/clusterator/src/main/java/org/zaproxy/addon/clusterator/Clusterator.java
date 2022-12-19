/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.clusterator;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Timestamp;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.clusterator.internal.ClusterConfig;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ActiveScanTableModel;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.view.ZapMenuItem;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JButton;
import javax.swing.JToolBar;

import static org.zaproxy.addon.clusterator.internal.Clusterer.cluster;


public class Clusterator extends ExtensionAdaptor {

	// The name is public so that other extensions can access it
	public static final String NAME = "Clusterator";

	// The i18n prefix, by default the package name - defined in one place to make it easier
	// to copy and change this example
	protected static final String PREFIX = "clusterator";

	/**
	 * Relative path (from add-on package) to load add-on resources.
	 *
	 * @see Class#getResource(String)
	 */
	private static final String RESOURCES = "resources";

	private static final ImageIcon ICON =
			new ImageIcon(Clusterator.class.getResource(RESOURCES + "/cake.png"));

	private static final String EXAMPLE_FILE = "example/ExampleFile.txt";

	private ZapMenuItem menuExample;
	private RightClickMsgMenu popupMsgMenuExample;
	private AbstractPanel statusPanel;

	private SimpleExampleAPI api;

	private static final Logger LOGGER = LogManager.getLogger(Clusterator.class);

	ExtensionActiveScan extensionActiveScan;

	private ExtensionActiveScan getExtAScan() {
		if (extensionActiveScan == null) {
			extensionActiveScan =
					Control.getSingleton()
							.getExtensionLoader()
							.getExtension(ExtensionActiveScan.class);
		}
		return extensionActiveScan;
	}

	public Clusterator() {
		super(NAME);
		setI18nPrefix(PREFIX);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		this.api = new SimpleExampleAPI();
		extensionHook.addApiImplementor(this.api);

		// As long as we're not running as a daemon
		if (hasView()) {
			extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
			extensionHook.getHookView().addStatusPanel(getStatusPanel());
		}
	}

	@Override
	public boolean canUnload() {
		// The extension can be dynamically unloaded, all resources used/added can be freed/removed
		// from core.
		return true;
	}

	@Override
	public void unload() {
		super.unload();

		// In this example it's not necessary to override the method, as there's nothing to unload
		// manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
		// are automatically removed by the base unload() method.
		// If you use/add other components through other methods you might need to free/remove them
		// here (if the extension declares that can be unloaded, see above method).
	}

	private AbstractPanel getStatusPanel() {
		if (statusPanel == null) {
			statusPanel = new AbstractPanel();
			statusPanel.setLayout(new BorderLayout());
			statusPanel.setName("!Clusterator");
			statusPanel.setIcon(ICON);

			JTextPane pane = new JTextPane();
			JScrollPane spane = new JScrollPane(pane);
			statusPanel.add(spane, BorderLayout.CENTER);
			pane.setContentType("text/html");
			pane.setEditable(false);
			pane.setText("Results will appear here. Run the ActiveScan before clicking the cluster button.");
			JToolBar toolbar = new JToolBar();
			JButton clusterActionButton = new JButton();
			clusterActionButton.setIcon(ICON);
			clusterActionButton.setText("Cluster latest scan results!");
			JTextPane w1 = new JTextPane();
			JLabel t1 = new JLabel();
			JTextPane w2 = new JTextPane();
			JLabel t2 = new JLabel();
			JTextPane w3 = new JTextPane();
			JLabel t3 = new JLabel();
			JTextPane w4 = new JTextPane();
			JLabel t4 = new JLabel();
			JTextPane w5 = new JTextPane();
			JLabel t5 = new JLabel();
			t1.setText("Response length:");
			t2.setText("Request length:");
			t3.setText("Response time:");
			t4.setText("Body text similarity:");
			t5.setText("Reflection:");
			w1.setText("1");
			w2.setText("0");
			w3.setText("0");
			w4.setText("0");
			w5.setText("0");
			toolbar.add(t1);
			toolbar.add(w1);
			toolbar.add(t2);
			toolbar.add(w2);
			toolbar.add(t3);
			toolbar.add(w3);
			toolbar.add(t4);
			toolbar.add(w4);
			toolbar.add(t5);
			toolbar.add(w5);
			//new ClusterConfig(sve iz tih paneova)
			statusPanel.add(toolbar, BorderLayout.PAGE_START);
			toolbar.add(clusterActionButton);

			clusterActionButton.addActionListener(
					new java.awt.event.ActionListener() {
						@Override
						public void actionPerformed(ActionEvent e) {
							ActiveScan as = getExtAScan().getLastScan();
							if (as != null) {
								int bestk = 10; //TODO ovo automatizirat/maknut
								ClusterConfig config = null;
								try {
									 config = new ClusterConfig(
											 Double.parseDouble(w1.getText()),
											 Double.parseDouble(w2.getText()),
											 Double.parseDouble(w3.getText()),
											 Double.parseDouble(w4.getText()),
											 Double.parseDouble(w5.getText())
									 );

								} catch(NumberFormatException ex) {
									pane.setText("One of the given values isn't a valid number.");
									return;
								}
								String output = generateText(as, bestk, config);
								pane.setText(output);
								writeToFile(output, new Date().toString());
								//TODO output to a file as well
							} else {
								pane.setText("No data available. Please run an ActiveScan.");
							}
						}
					});
		}
		return statusPanel;
	}

	private void writeToFile(String string, String path) {
		try (Writer writer = new BufferedWriter(
				new OutputStreamWriter(
						new FileOutputStream(path), StandardCharsets.UTF_8))) {
			writer.write(string);
		} catch (IOException e) {
		}
	}
	private String generateText(ActiveScan as, int bestk, ClusterConfig config) {
		ActiveScanTableModel tmodel = as.getMessagesTableModel();
		return cluster(tmodel, bestk, config);
	}

	private ZapMenuItem getMenuExample() {
		if (menuExample == null) {
			menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

			menuExample.addActionListener(
					e -> {
						// This is where you do what you want to do.
						// In this case we'll just show a popup message.
						View.getSingleton()
								.showMessageDialog(
										Constant.messages.getString(PREFIX + ".topmenu.tools.msg"));
						// And display a file included with the add-on in the Output tab
						displayFile(EXAMPLE_FILE);
					});
		}
		return menuExample;
	}

	private void displayFile(String file) {
		if (!View.isInitialised()) {
			// Running in daemon mode, shouldnt have been called
			return;
		}
		try {
			File f = new File(Constant.getZapHome(), file);
			if (!f.exists()) {
				// This is something the user should know, so show a warning dialog
				View.getSingleton()
						.showWarningDialog(
								Constant.messages.getString(
										Clusterator.PREFIX + ".error.nofile",
										f.getAbsolutePath()));
				return;
			}
			// Quick way to read a small text file
			String contents = new String(Files.readAllBytes(f.toPath()));
			// Write to the output panel
			View.getSingleton().getOutputPanel().append(contents);
			// Give focus to the Output tab
			View.getSingleton().getOutputPanel().setTabFocus();
		} catch (Exception e) {
			// Something unexpected went wrong, write the error to the log
			LOGGER.error(e.getMessage(), e);
		}
	}

	private RightClickMsgMenu getPopupMsgMenuExample() {
		if (popupMsgMenuExample == null) {
			popupMsgMenuExample =
					new RightClickMsgMenu(
							this, Constant.messages.getString(PREFIX + ".popup.title"));
		}
		return popupMsgMenuExample;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(PREFIX + ".desc");
	}
}
