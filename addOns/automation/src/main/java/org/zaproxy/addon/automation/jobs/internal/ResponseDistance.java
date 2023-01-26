package org.zaproxy.addon.automation.jobs.internal;

import org.apache.commons.lang.StringUtils;

import java.util.Map;

public class ResponseDistance implements Distance {

	private ClusterConfig config;

	public ResponseDistance(ClusterConfig config) {
		this.config = config;
	}

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
		return sum;
	}
}