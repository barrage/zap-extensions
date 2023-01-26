package org.zaproxy.addon.automation.jobs.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.zaproxy.addon.automation.jobs.internal.Clusterer.maxValues;

public class ClusterReference {
	private final String rawRequest;
	private final Map<String, Double> fields;
	public int responseLength;
	public int requestLength;
	public int responseTime;
	public int reflected;

	public double responseLengthScaled;
	public double requestLengthScaled;
	public double responseTimeScaled;

	public int href;

	public String getResponseBody() {
		return responseBody;
	}

	private String responseBody;
	private HistoryReference historyReference;

	private static Logger log = LogManager.getLogger(ClusterReference.class);


	//used for generating centroids or averages for clustering purposes, doesn't contain a HistoryReference of an actual request/response
	public ClusterReference(Map<String, Double> fields, String responseBody) {
		this.fields = fields;
		this.responseBody = responseBody;
		this.responseLength = fields.get("responseLength").intValue();
		this.requestLength = fields.get("requestLength").intValue();
		this.reflected = fields.get("reflected").intValue();
		this.responseTime = fields.get("responseTime").intValue();
		this.requestLengthScaled = (double) this.requestLength / maxValues.requestLength;
		this.responseLengthScaled = (double) this.responseLength / maxValues.responseLength;
		this.responseTimeScaled = (double) this.responseTime / maxValues.responseTime;
		this.fields.put("requestLengthScaled", requestLengthScaled);
		this.fields.put("responseLengthScaled", responseLengthScaled);
		this.fields.put("responseTimeScaled", responseTimeScaled);
		this.rawRequest = String.format("responseLength:%d, requestLength:%d, Reflected:%d", responseLength, requestLength, reflected);
	}

	//has a history reference to an actual request/response
	public ClusterReference(HistoryReference href, int responseTime, String responseBody, ClusterReference maxValues) {
		this(href.getResponseBodyLength(),
				href.getRequestBodyLength(),
				isReflected(href),
				responseTime,
				responseBody
		);
		this.requestLengthScaled = (double) this.requestLength / maxValues.requestLength;
		this.responseLengthScaled = (double) this.responseLength / maxValues.responseLength;
		this.responseTimeScaled = (double) this.responseTime / maxValues.responseTime;
		this.fields.put("requestLengthScaled", requestLengthScaled);
		this.fields.put("responseLengthScaled", responseLengthScaled);
		this.fields.put("responseTimeScaled", responseTimeScaled);
		this.historyReference = href;
		this.href = href.getHistoryId();
	}

	private static int isReflected(HistoryReference href) {
		if (href == null) return -1;
		String response = "";
		String payload = "";
		try {
			if (href.getHttpMessage() == null) return -1;
			response = href.getHttpMessage().getResponseBody().toString();
			payload = href.getHttpMessage().getNote();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return response.contains(payload) ? 1 : 0;
	}

	//used only for the maxValues from outside this class
	public ClusterReference(int responseLength, int requestLength, int reflected, int responseTime, String responseBody) {

		this.responseLength = responseLength;
		this.requestLength = requestLength;
		this.fields = new HashMap<>();
		fields.put("responseTime", (double) responseTime);
		fields.put("responseLength", (double) responseLength);
		fields.put("requestLength", (double) requestLength);
		fields.put("reflected", (double) reflected);
		this.responseTime = responseTime;
		this.responseBody = responseBody;
		this.rawRequest = String.format("responseLength:%d, PayloadLength:%d, Reflected:%d", responseLength, requestLength, reflected);
	}

	public Map<String, Double> getFields() {
		if (fields == null) {
			System.out.println("problem with " + this);
		}
		return fields;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ClusterReference that = (ClusterReference) o;
		return responseLength == that.responseLength && requestLength == that.requestLength && reflected == that.reflected && Objects.equals(rawRequest, that.rawRequest) && Objects.equals(fields, that.fields) && Objects.equals(href, that.href);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rawRequest, fields, responseLength, requestLength, reflected, href);
	}

	@Override
	public String toString() {
		boolean debug = false;
		String s = historyReference == null ? "null" : String.valueOf(historyReference.getHistoryId());
		if (!debug) {
			StringBuilder sb = new StringBuilder();
			sb.append("{");
			for (Map.Entry<String, Double> entry : fields.entrySet()) {
				if (!entry.getKey().contains("Scaled")) {
					sb.append(entry).append(',');
				}
			}
			sb.append(" href=").append(s).append("}");
			return sb.toString();
		} else {
			return "{" + fields + " href=" + s + "}";
		}
	}
}
