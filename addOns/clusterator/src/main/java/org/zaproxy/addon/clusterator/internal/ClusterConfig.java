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
}
