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

	public static String cluster(ActiveScanTableModel tmodel, int bestk, ClusterConfig config) {
//		ovo nam je return type ako necemo doslovni string
//		Map<ClusterReference, List<ClusterReference>> clusters = null;
		Map<Integer, List<ClusterReference>> codeToCref = arrangeByStatusCode(tmodel);
		StringBuilder sb = new StringBuilder();
		clusterWithinStatusCode(codeToCref, sb, bestk, config);
		return sb.toString();
	}

	private static void clusterWithinStatusCode(Map<Integer, List<ClusterReference>> codeToCref, StringBuilder sb, int bestk, ClusterConfig config) {
		for (Map.Entry<Integer, List<ClusterReference>> statusBasedCluster : codeToCref.entrySet()) {
			Map<ClusterReference, List<ClusterReference>> result = KMeans.fit(statusBasedCluster.getValue(), bestk, new ResponseDistance(config), 100);
			for (Map.Entry<ClusterReference, List<ClusterReference>> entry : result.entrySet()) {
				sb.append("---CLUSTER CENTROID---STATUS CODE:").append(statusBasedCluster.getKey()).append(entry.getKey()).append("<br>");
				List<ClusterReference> crefs = entry.getValue();
				for (ClusterReference cref : crefs) {
					sb.append(cref).append("<br>");
				}
			}
		}
	}

	private static Map<Integer, List<ClusterReference>> arrangeByStatusCode(ActiveScanTableModel tmodel) {
		Map<Integer, List<ClusterReference>> codeToCrefs = new HashMap<>();
		int n = tmodel.getRowCount();
		for (int i = 0; i < n; i++) {
			DefaultHistoryReferencesTableEntry entry = tmodel.getEntry(i);
			HistoryReference href = entry.getHistoryReference();
			int statusCode = href.getStatusCode();

			if (codeToCrefs.containsKey(statusCode)) {
				codeToCrefs.get(statusCode).add(new ClusterReference(href));
			} else {
				List<ClusterReference> list = new ArrayList<>();
				list.add(new ClusterReference(href));
				codeToCrefs.put(statusCode, list);
			}
		}
		return codeToCrefs;
	}

	public static double silhouette(Map<ClusterReference, List<ClusterReference>> clustered, Distance distance) {
		System.out.println("Computing silhoutte coefficient...");
		ArrayList<Double> S = new ArrayList<Double>();
		double clusteringMean = 0;
		int count = 0;
		System.out.println("Number of clusters : " + clustered.entrySet().size());
		for (Map.Entry<ClusterReference, List<ClusterReference>> entry : clustered.entrySet()) {
			System.out.println("Computing Silhouette Coeff Cluster " + count);
			double clusterMean = 0;
			for (ClusterReference d : entry.getValue()) {
				double A = 0;
				double B = 0;
				double sumA = 0;
				for (ClusterReference notD : entry.getValue()) {
					if (d.equals(notD)) {
						continue;
					}
					sumA += distance.calculate(d, notD);
				}
				int clusterMembers = entry.getValue().size();
				if (clusterMembers > 1) {
					A = sumA / (double) (clusterMembers - 1);
				}

				double minDist = Double.MAX_VALUE;
				Map.Entry<ClusterReference, List<ClusterReference>> closestCluster = null;
				for (Map.Entry<ClusterReference, List<ClusterReference>> c : clustered.entrySet()) {
					if (c == entry) {
						continue;
					}
					if (c.getValue().size() == 0) {
						continue;
					}
					double dist = distance.calculate(entry.getKey(), c.getKey());
					if (dist < minDist) {
						minDist = dist;
						closestCluster = c;
					}
				}

				double sumB = 0;
				for (ClusterReference D : closestCluster.getValue()) {
					if (d == D) {
						continue;
					}
					sumB += distance.calculate(d, D);
				}
				B = sumB / (double) (closestCluster.getValue().size());

				double Si = (B - A) / Math.max(B, A);
				if (Math.max(B, A) == 0) {
					Si = 0;
				}
				clusterMean += Si;
			}

			if (entry.getValue().size() > 0) {
				clusterMean = clusterMean / entry.getValue().size();
			}

			System.out.println("Silhoutte Coefficient for Cluster " + count + " : " + clusterMean);
			System.out.println();
			S.add(clusterMean);
			count++;
			clusteringMean += clusterMean;
		}
		clusteringMean = clusteringMean / clustered.entrySet().size();
		return clusteringMean;
	}
//ovo je bilo u cluster metodi, pomoc ce pri optimizaciji k ali ne jos ocito
	//		Map<Integer, Double> siluete = new HashMap<>();
//		for (int k = 26; k <= 26; k++) {
//			clusters = KMeans.fit(crefs, k, new ResponseDistance(), 100);
//			double s = silhouette(clusters, new ResponseDistance());
//			siluete.put(clusters.size(), s);
//
//			int finalK = k;
//			clusters.forEach((key, value) -> {
//				System.out.println("-------------------------- CLUSTER ----------------------------");
//				System.out.println(key);
//				Set<String> members = value.stream().map(ClusterReference::getRawRequest).collect(toSet());
//				for (String m : members) {
//					System.out.println(m);
//				}
//				System.out.printf("k = %d, s = %f\n", finalK, s);
//				System.out.println();
//				System.out.println();
//			});
//		}
//		System.out.println("ERRORS______________________________");
//		double bestSil = Double.MIN_VALUE;
//		int bestk = Integer.MIN_VALUE;
//		for (Map.Entry<Integer, Double> d : siluete.entrySet()) {
//			System.out.println(d.getKey());
//			System.out.println(d.getValue());
//			if(d.getValue()>bestSil){
//				bestk = d.getKey();
//			}
//		}
}


