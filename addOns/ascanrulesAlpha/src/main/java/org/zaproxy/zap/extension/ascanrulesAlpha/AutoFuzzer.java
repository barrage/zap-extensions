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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.network.HttpResponseBody;

import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.io.IOException;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Active scan rule that fuzzes all given fields with user input passed through Radamsa fuzzer.
 */
public class AutoFuzzer extends AbstractAppParamPlugin {

	private static final String MESSAGE_PREFIX = "ascanalpha.autofuzzer.";
	private static final String fuzzersFolder = Constant.getZapHome() + "fuzzers";
	private static final String configFile = fuzzersFolder + File.separator + "autofuzzer.config";
	private static final String genFolder = fuzzersFolder + File.separator + "gen";

	private int quantity = 0;
	private String radamsaPath = null;
	private String outputPath = null;
	private List<String> userPayloads = null;
	private List<String> generatedPayloads = null;
	private static Logger log = LogManager.getLogger(AutoFuzzer.class);

	@Override
	public int getId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is https://github.com/zaproxy/zaproxy/blob/main/docs/scanners.md
		 */
		return 50009;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public boolean targets(
			TechSet technologies) {
		return true;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getOtherInfo() {
		return Constant.messages.getString(MESSAGE_PREFIX + "other");
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	@Override
	public int getCategory() {
		return Category.MISC;
	}

	@Override
	public void scan(HttpMessage msg, String param, String value) {
		try {
			parseConfig();
		} catch (NumberFormatException ex) {
			log.error("Error in config file /ZAP home/fuzzers/autofuzzer.config, view documentation");
		}
		try {
			for (int j = 0; j < userPayloads.size(); j++) {
				new File(genFolder + File.separator + j).mkdirs();
				String outputPerInput = j + File.separator + getFilePattern();
				generatePayloads(userPayloads.get(j), quantity, outputPerInput);
				if (this.generatedPayloads == null) {
					this.generatedPayloads = new ArrayList<>();
				}
				for (int i = 1; i <= quantity; i++) {
					String loadable = genFolder + File.separator + insertNumber(outputPerInput, i);
					this.generatedPayloads.addAll(loadFile(loadable));
				}
				for (String generatedPayload : this.generatedPayloads) {
					if (this.isStop()) {
						break;
					}
					HttpMessage testMsg = getNewMsg();
					testMsg.setNote(generatedPayload);
					setParameter(testMsg, param, generatedPayload);
					sendAndReceive(testMsg);
				}
			}
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
	}

	private String insertNumber(String outputPerInput, int i) {
		return String.format(outputPerInput.replaceAll("%n", "%d"), i);
	}

	private void parseConfig() {
		List<String> lines = loadFile(configFile);
		this.radamsaPath = lines.get(0);
		this.userPayloads = loadFile(lines.get(1));
		this.outputPath = lines.get(2);
		this.quantity = Integer.parseInt(lines.get(3));
	}

	private static void generatePayloads(
			String userPayload, int quantity, String outputName) throws Exception {
		String scriptName = "genScript1.sh";
		File script = new File(genFolder + File.separator + scriptName);
		File output = new File(genFolder + File.separator + outputName);
		try (Writer writer = new BufferedWriter(
				new OutputStreamWriter(
						new FileOutputStream(script), StandardCharsets.UTF_8))) {
			String s = "#!/bin/bash\n" + "echo \"" + userPayload +
					"\" | radamsa -n " + quantity +
					" -o \"" + output.getAbsolutePath() + "\"";
			writer.write(s);
		}
		String[] command = {"bash", script.getAbsolutePath()};
		new ProcessBuilder(command).inheritIO().start().waitFor();
	}

	private String getFilePattern() {
		String outputStr = outputPath.toLowerCase().trim();
		return outputStr.substring(outputStr.lastIndexOf(File.separatorChar) + 1);
	}

	private List<String> loadFile(String file) {
		List<String> strings = new ArrayList<>();
		BufferedReader reader = null;
		File f = new File(file);
		if (!f.exists()) {
			log.error("No such file: {}", f.getAbsolutePath());
			return strings;
		}
		try {
			String line;
			reader = new BufferedReader(new FileReader(f));
			while ((line = reader.readLine()) != null) {
				if (!line.startsWith("#") && line.length() > 0) {
					strings.add(line);
				}
			}
		} catch (IOException e) {
			log.error("Error on opening/reading example error file. Error: {}", e.getMessage(), e);
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					log.debug("Error on closing the file reader. Error: {}", e.getMessage(), e);
				}
			}
		}
		return strings;
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		return 0;
	}

	@Override
	public int getWascId() {
		return 0;
	}
}