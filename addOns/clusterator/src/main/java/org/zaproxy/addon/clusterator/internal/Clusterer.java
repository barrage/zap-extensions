package org.zaproxy.addon.clusterator.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.ascan.ActiveScanTableModel;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

public class Clusterer {

	private static Logger log = LogManager.getLogger(Clusterer.class);
	public static ClusterReference maxValues = null;

	public static String cluster(List<HistoryReference> hrefs, int bestk, ClusterConfig config) {
//		ovo nam je return type ako necemo doslovni string
//		Map<ClusterReference, List<ClusterReference>> clusters = null;
		Map<Integer, List<ClusterReference>> codeToCref = arrangeByStatusCode(hrefs);
		StringBuilder sb = new StringBuilder();
		clusterWithinStatusCode(codeToCref, sb, bestk, config);
		return sb.toString();
	}

	private static void clusterWithinStatusCode(Map<Integer, List<ClusterReference>> codeToCref, StringBuilder sb, int bestk, ClusterConfig config) {
		Distance distance = new ResponseDistance(config);
		for (Map.Entry<Integer, List<ClusterReference>> statusBasedCluster : codeToCref.entrySet()) {
			Map<ClusterReference, List<ClusterReference>> result = KMeans.fit(statusBasedCluster.getValue(), bestk, distance, 100);
			for (Map.Entry<ClusterReference, List<ClusterReference>> entry : result.entrySet()) {
				sb.append("Centroid, status code:").append(statusBasedCluster.getKey()).append(entry.getKey()).append("\n<br>");
				List<ClusterReference> crefs = entry.getValue();
				for (ClusterReference cref : crefs) {
					sb.append(cref).append("\n<br>");
				}
			}
		}
	}

	private static Map<Integer, List<ClusterReference>> arrangeByStatusCode(List<HistoryReference> hrefs) {
		Map<Integer, List<ClusterReference>> codeToCrefs = new HashMap<>();
		int maxResponseTime = 0;
		int maxResponseLength = 0;
		int maxRequestLength = 0;
		for (HistoryReference href : hrefs) {
			String responseBody = "";
			int responseTime = 0;
			int responseLength = 0;
			int requestLength = 0;
			try {
				responseBody = href.getHttpMessage().getResponseBody().toString();
				responseTime = href.getHttpMessage().getTimeElapsedMillis();
				requestLength = href.getHttpMessage().getRequestBody().length();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
			responseLength = responseBody.length();
			maxResponseTime = Math.max(responseTime, maxResponseTime);
			maxResponseLength = Math.max(responseLength, maxResponseLength);
			maxRequestLength = Math.max(requestLength, maxRequestLength);
		}
		maxValues = new ClusterReference(maxResponseLength, maxRequestLength, 1, maxResponseTime, "dummy");

		for (HistoryReference href : hrefs) {
			int statusCode = href.getStatusCode();
			String responseBody = "";
			int responseTime = 0;
			try {
				responseBody = href.getHttpMessage().getResponseBody().toString();
				responseTime = href.getHttpMessage().getTimeElapsedMillis();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
			if (codeToCrefs.containsKey(statusCode)) {
				codeToCrefs.get(statusCode).add(new ClusterReference(href, responseTime, responseBody, maxValues));
			} else {
				List<ClusterReference> list = new ArrayList<>();
				list.add(new ClusterReference(href, responseTime, responseBody, maxValues));
				codeToCrefs.put(statusCode, list);
			}
		}
		return codeToCrefs;
	}
}


