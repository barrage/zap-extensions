package org.zaproxy.addon.clusterator.internal;

public class ClusterConfig {

	double responseLengthWeight;
	double requestLengthWeight;
	double responseTimeWeight;
	double similarityWeight;
	double reflectedWeight;

	public ClusterConfig(double responseLengthWeight, double requestLengthWeight, double responseTimeWeight, double similarityWeight, double reflectedWeight) {
		this.responseLengthWeight = responseLengthWeight;
		this.requestLengthWeight = requestLengthWeight;
		this.responseTimeWeight = responseTimeWeight;
		this.similarityWeight = similarityWeight;
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
	public double getSimilarityWeight() {
		return similarityWeight;
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
				", similarityWeight=" + similarityWeight +
				", reflectedWeight=" + reflectedWeight +
				'}';
	}
}
