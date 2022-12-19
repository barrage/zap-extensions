package org.zaproxy.addon.clusterator.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ClusterReference {
	private final String rawRequest;
	private final Map<String, Double> fields;
	private int contentLength;
	private int payloadLength;
	private int reflected;
	private HistoryReference href;

	private static Logger log = LogManager.getLogger(ClusterReference.class);


	//used for generating centroids or averages for clustering purposes, doesn't contain a HistoryReference of an actual request/response
	public ClusterReference(Map<String, Double> fields) {
		this.fields = fields;
		this.contentLength = fields.get("contentLength").intValue();
		this.payloadLength = fields.get("payloadLength").intValue();
		this.reflected = fields.get("reflected").intValue();
		this.rawRequest = String.format("Content-length:%d, PayloadLength:%d, Reflected:%d", contentLength, payloadLength, reflected);
	}

	//has a history reference to an actual request/response
	public ClusterReference(HistoryReference href) {
		this(href.getResponseBodyLength(),
				href.getRequestBodyLength(),
				isReflected(href));
		this.href = href;
	}

	private static int isReflected(HistoryReference href) {
		if (href == null) return -1;
		String note = "";
		try {
			if (href.getHttpMessage() == null) return -1;
			note = href.getHttpMessage().getNote();
			List<Alert> alerts = href.getAlerts();
			log.error("alerts size: " + alerts.size());
			for (Alert alert : alerts) {
				log.error("THIS IS THE attack: " + alert.getAttack());
				log.error("THIS IS THE param: " + alert.getParam());
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		if (note.equals("REFLECTED NEW")) {
			return 2;
		} else if (note.equals("REFLECTED BASE")) {
			return 3;
		}
		return 4;
	}

	private ClusterReference(int contentLength, int payloadLength, int reflected) {

		this.contentLength = contentLength;
		this.payloadLength = payloadLength;
		this.fields = new HashMap<>();
		fields.put("contentLength", (double) contentLength);
		fields.put("payloadLength", (double) payloadLength);
		fields.put("reflected", (double) reflected);
		this.rawRequest = String.format("Content-length:%d, PayloadLength:%d, Reflected:%d", contentLength, payloadLength, reflected);
	}

	public HistoryReference getHref() {
		return href;
	}

	public String getRawRequest() {
		return rawRequest;
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
		return contentLength == that.contentLength && payloadLength == that.payloadLength && reflected == that.reflected && Objects.equals(rawRequest, that.rawRequest) && Objects.equals(fields, that.fields) && Objects.equals(href, that.href);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rawRequest, fields, contentLength, payloadLength, reflected, href);
	}

	@Override
	public String toString() {
		String s = href == null ? "null" : String.valueOf(href.getHistoryId());
		return "cref{" +
				"fields=" + fields +
				", href=" + s +
				'}';
	}
}
