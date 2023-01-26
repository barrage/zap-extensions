package org.zaproxy.addon.clusterator.internal;

import org.apache.commons.lang.StringUtils;

import java.util.Map;

public class ResponseDistance implements Distance {

	private ClusterConfig config;

	public ResponseDistance(ClusterConfig config) {
		this.config = config;
	}

	//    cosine, gore suma produkata svih znacajki, dolje sqrt(ai)*sqrt(bi)
//    @Override
//    public double calculate(Map<String, Double> f1, Map<String, Double> f2) {
//        double cosine = 0;
//        for (String key : f1.keySet()) {
//            Double ai = f1.get(key);
//            Double bi = f2.get(key);
//            cosine += ai * bi;
//        }
//        double suma = 0;
//        for(Double ai : f1.values()){
//            suma+=Math.pow(ai, 2);
//        }
//        suma = Math.sqrt(suma);
//        cosine/=suma;
//        suma = 0;
//        for(Double bi : f2.values()){
//            suma+=Math.pow(bi, 2);
//        }
//        suma = Math.sqrt(suma);
//        cosine/=suma;
//        return cosine;
//    }

	//    osnovna
	@Override
	public double calculate(ClusterReference crefA, ClusterReference crefB) {
		double sum = 0;
		Map<String, Double> f1 = crefA.getFields();
		Map<String, Double> f2 = crefB.getFields();

		for (String key : f1.keySet()) {
			Double v1 = f1.get(key);
			Double v2 = f2.get(key);

			if (v1 != null && v2 != null) {
				switch (key) {
					case "requestLengthScaled":
						sum += config.getRequestLengthWeight() * Math.abs(v1 - v2);
						break;
					case "responseLengthScaled":
						sum += config.getResponseLengthWeight() * Math.abs(v1 - v2);
						break;
					case "reflected":
						sum += config.getReflectedWeight() * Math.abs(v1 - v2);
						break;
					case "responseTimeScaled":
						sum += config.getResponseTimeWeight() * Math.abs(v1 - v2);
						break;
					default:
				}
			}
		}
		if (config.getSimilarityWeight() > 0) {
			double similarity = calculateSimilarity(crefA.getResponseBody(), crefB.getResponseBody());
			sum += config.getSimilarityWeight() * similarity;
		}
		return sum;
	}

	private double calculateSimilarity(String body1, String body2) {
		if (body1 == null || body2 == null) return 0;
		int editDistance = StringUtils.getLevenshteinDistance(body1, body2);
		return 1.0 - (double) editDistance / Math.max(body1.length(), body2.length());
	}
}