/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jfree.chart.ChartUtils;
import org.jfree.chart.plot.PlotOrientation;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.ClusterResponsesJobDialog;
import org.zaproxy.addon.automation.jobs.internal.ClusterReference;
import org.zaproxy.addon.automation.jobs.internal.Clusterer;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.zaproxy.addon.automation.jobs.internal.ClusterConfig;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import static org.zaproxy.addon.automation.jobs.internal.Clusterer.cluster;

public class ClusterResponsesJob extends AutomationJob {

	private static Logger log = LogManager.getLogger(ClusterResponsesJob.class);

	public static final String JOB_NAME = "clusterResponses";
	private static final String fuzzersFolder = Constant.getZapHome() + "fuzzers";
	private static final String reportFolder = fuzzersFolder + File.separator + "clusterReports";

	private static final String hrefsFolder = reportFolder + File.separator + "historyReferences";
	private ExtensionActiveScan extensionActiveScan;
	private Data data;
	private Parameters parameters = new Parameters();
	private static boolean endJob;

	public ClusterResponsesJob() {
		this.data = new Data(this, parameters);
	}

	@Override
	public void verifyParameters(AutomationProgress progress) {
		try {
			Double.parseDouble(this.getParameters().getResponseLengthWeight());
			Double.parseDouble(this.getParameters().getRequestLengthWeight());
			Double.parseDouble(this.getParameters().getResponseTimeWeight());
			Double.parseDouble(this.getParameters().getReflectedWeight());
		} catch (Exception e) {
			progress.error(Constant.messages.getString("automation.dialog.clusterResponses.error.nan"));
		}
	}

	@Override
	public void applyParameters(AutomationProgress progress) {
	}

	@Override
	public void runJob(AutomationEnvironment env, AutomationProgress progress) {
		setEndJob(false);
		ActiveScan as = getExtAScan().getLastScan();
		String output = null;
		try {
			output = generateText(as, new ClusterConfig(
					Double.parseDouble(this.getParameters().getResponseLengthWeight()),
					Double.parseDouble(this.getParameters().getRequestLengthWeight()),
					Double.parseDouble(this.getParameters().getResponseTimeWeight()),
					Double.parseDouble(this.getParameters().getReflectedWeight())
			));
		} catch (Exception e) {
			// Will have warned the user during the verify
			return;
		}
		writeToFile(output,
				reportFolder + File.separator + "AF" +
						new Date() + ".txt");
		Map<ClusterReference, List<ClusterReference>> data = Clusterer.result;
		try {
			plotGraphs(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		setEndJob(true);
	}

	public static void setEndJob(boolean bool) {
		endJob = bool;
	}

	@Override
	public String getType() {
		return JOB_NAME;
	}

	@Override
	public Order getOrder() {
		return Order.AFTER_ATTACK;
	}

	@Override
	public Object getParamMethodObject() {
		return null;
	}

	@Override
	public String getParamMethodName() {
		return null;
	}

	@Override
	public void showDialog() {
		new ClusterResponsesJobDialog(this).setVisible(true);
	}

	@Override
	public String getSummary() {
		return Constant.messages.getString(
				"automation.dialog.clusterResponses.summary",
				this.getData().getParameters().getResponseLengthWeight(),
				this.getData().getParameters().getRequestLengthWeight(),
				this.getData().getParameters().getResponseTimeWeight(),
				this.getData().getParameters().getReflectedWeight()
		);
	}

	@Override
	public Data getData() {
		return data;
	}

	@Override
	public Parameters getParameters() {
		return this.parameters;
	}

	public static void plotGraphs(Map<ClusterReference, List<ClusterReference>> clusters) throws IOException, NoSuchFieldException, IllegalAccessException {
		String[] params = {"href", "responseLength", "requestLength", "responseTime", "reflected"};
		for (int i = 0; i < params.length; i++) {
			for (int j = i + 1; j < params.length; j++) {
				XYSeriesCollection dataset = new XYSeriesCollection();
				int clusterNum = 0;
				for (Map.Entry<ClusterReference, List<ClusterReference>> entry : clusters.entrySet()) {
					XYSeries series = new XYSeries("Cluster " + clusterNum);
					for (ClusterReference ref : entry.getValue()) {
						series.add(((Integer) ref.getClass().getField(params[i]).get(ref)).doubleValue(), ((Integer) ref.getClass().getField(params[j]).get(ref)).doubleValue());
					}
					dataset.addSeries(series);
					clusterNum++;
				}
				JFreeChart chart = ChartFactory.createScatterPlot(
						params[i] + " vs " + params[j],
						params[i],
						params[j],
						dataset,
						PlotOrientation.VERTICAL,
						true,
						true,
						false
				);
				OutputStream out = new FileOutputStream(reportFolder + File.separator + params[i] + "-" + params[j] + ".png");
				ChartUtils.writeChartAsPNG(out,
						chart,
						800,
						600);

			}
		}
	}

	public String generateText(ActiveScan as, ClusterConfig config) {
		List<Integer> ids = as.getMessagesIds();
		log.debug("Number of references to be clustered: " + ids.size());
		List<HistoryReference> hrefs = new ArrayList<>();
		for (Integer id : ids) {
			try {
				hrefs.add(new HistoryReference(id));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		try {
			writeHrefsToFiles(hrefs);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return cluster(hrefs, 10, config);
	}

	private void writeHrefsToFiles(List<HistoryReference> hrefs) throws HttpMalformedHeaderException, DatabaseException {
		for(HistoryReference href : hrefs){
			HttpMessage msg = href.getHttpMessage();
			StringBuilder sb = new StringBuilder();
			sb.append(msg.getRequestBody()).append("\n");
			sb.append(msg.getResponseBody()).append("\n");
			writeToFile(sb.toString(), hrefsFolder + File.separator + href.getHistoryId() + ".txt");
		}
	}


	private void writeToFile(String string, String path) {
		new File(path.substring(0, path.lastIndexOf(File.separator))).mkdirs();
		try (Writer writer = new BufferedWriter(
				new OutputStreamWriter(
						new FileOutputStream(path), StandardCharsets.UTF_8))) {
			writer.write(string);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private ExtensionActiveScan getExtAScan() {
		if (extensionActiveScan == null) {
			extensionActiveScan =
					Control.getSingleton()
							.getExtensionLoader()
							.getExtension(ExtensionActiveScan.class);
		}
		return extensionActiveScan;
	}

	public static class Data extends JobData {
		private Parameters parameters;

		public Data(AutomationJob job, Parameters parameters) {
			super(job);
			this.parameters = parameters;
		}

		public Parameters getParameters() {
			return parameters;
		}
	}

	public static class Parameters extends AutomationData {
		String responseLengthWeight;
		String requestLengthWeight;
		String responseTimeWeight;
		String reflectedWeight;

		public String getResponseLengthWeight() {
			return responseLengthWeight;
		}

		public void setResponseLengthWeight(String responseLengthWeight) {
			this.responseLengthWeight = responseLengthWeight;
		}

		public String getRequestLengthWeight() {
			return requestLengthWeight;
		}

		public void setRequestLengthWeight(String requestLengthWeight) {
			this.requestLengthWeight = requestLengthWeight;
		}

		public String getResponseTimeWeight() {
			return responseTimeWeight;
		}

		public void setResponseTimeWeight(String responseTimeWeight) {
			this.responseTimeWeight = responseTimeWeight;
		}

		public String getReflectedWeight() {
			return reflectedWeight;
		}

		public void setReflectedWeight(String reflectedWeight) {
			this.reflectedWeight = reflectedWeight;
		}
	}
}
