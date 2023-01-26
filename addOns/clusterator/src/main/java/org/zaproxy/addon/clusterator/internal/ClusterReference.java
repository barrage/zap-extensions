package org.zaproxy.addon.clusterator.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpMessage;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLOutput;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.zaproxy.addon.clusterator.internal.Clusterer.maxValues;

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

	public String getResponseBody() {
		return responseBody;
	}

	private String responseBody;
	private HistoryReference href;

	private static Logger log = LogManager.getLogger(ClusterReference.class);

	private static final Pattern JAVASCRIPT_PATTERN =
			Pattern.compile("<script[^>]*>.*?</script>", Pattern.DOTALL);

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
		this.href = href;
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

	private static int isReflectedk(HistoryReference href) { //TODO remove
		if (href == null) return -1;
		String request = "";
		String response = "";
		try {
			if (href.getHttpMessage() == null) return -1;
			request = href.getHttpMessage().getRequestBody().toString();
			response = href.getHttpMessage().getResponseBody().toString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		String[] params = parseParameters(request);
		return doesResponseContainAnyParam(response, params, href) ? 1 : 0;
	}

	public static String[] parseParameters(String request) {
		String[] parameters = request.split("&");
		for (int i = 0; i < parameters.length; i++) {
			String[] paramValuePair = parameters[i].split("=");
			if (paramValuePair.length > 1) {
				parameters[i] = paramValuePair[1];
			} else {
				parameters[i] = "";
			}
		}
		return parameters;
	}

	private static boolean doesResponseContainAnyParam(String response, String[] params, HistoryReference href) {
		response = response.toLowerCase();
		for (String param : params) {
			if ("".equals(param)) continue;
			param = param.toLowerCase();
			param = URLDecoder.decode(param, StandardCharsets.UTF_8);
			int start = response.indexOf(param);
			if (start >= 0) {
				return true;
			}
		}
		return false;
	}


	public static int countJavaScriptLines(String responseBody) {
		int lineCount = 0;
		Matcher matcher = JAVASCRIPT_PATTERN.matcher(responseBody);
		while (matcher.find()) {
			String script = matcher.group();
			lineCount += script.split("\n").length;
		}
		return lineCount;
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

	public HistoryReference getHref() {
		return href;
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
		boolean debug = true;
		String s = href == null ? "null" : String.valueOf(href.getHistoryId());
		if (!debug) {
			StringBuilder sb = new StringBuilder();
			sb.append("{");
			for (Map.Entry<String, Double> entry : fields.entrySet()) {
				if (!entry.getKey().contains("Scaled")) {
					sb.append(entry).append(',');
				}
			}
			sb.append(", href=").append(s).append("}");
			return sb.toString();
		} else {
			return "{" + fields + ", href=" + s + "}";
		}
	}
}
