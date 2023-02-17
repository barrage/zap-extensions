package org.zaproxy.addon.automation.jobs.internal;

public class ClusterConfig {
	double responseLengthWeight;
	double requestLengthWeight;
	double responseTimeWeight;
	double reflectedWeight;

	public ClusterConfig(double responseLengthWeight, double requestLengthWeight, double responseTimeWeight, double reflectedWeight) {
		this.responseLengthWeight = responseLengthWeight;
		this.requestLengthWeight = requestLengthWeight;
		this.responseTimeWeight = responseTimeWeight;
		this.reflectedWeight = reflectedWeight;
	}

	public double getResponseLengthWeight() {
		return responseLengthWeight;
	}

	public double getRequestLengthWeight() {
		return requestLengthWeight;
	}

	public double getResponseTimeWeight() {
		return responseTimeWeight;
	}

	public double getReflectedWeight() {
		return reflectedWeight;
	}

	@Override
	public String toString() {
		return "ClusterConfig{" +
				"responseLengthWeight=" + responseLengthWeight +
				", requestLengthWeight=" + requestLengthWeight +
				", responseTimeWeight=" + responseTimeWeight +
				", reflectedWeight=" + reflectedWeight +
				'}';
	}
}
