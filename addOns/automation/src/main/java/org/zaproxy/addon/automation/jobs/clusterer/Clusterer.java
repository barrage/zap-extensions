/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.automation.jobs.clusterer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;

public class Clusterer {

    private static Logger log = LogManager.getLogger(Clusterer.class);
    public static ClusterReference maxValues = null;

    public static Map<ClusterReference, List<ClusterReference>> result = null;

    public static String cluster(List<HistoryReference> hrefs, int bestk, ClusterConfig config) {
        Map<Integer, List<ClusterReference>> codeToCref = arrangeByStatusCode(hrefs);
        StringBuilder sb = new StringBuilder();
        result = clusterWithinStatusCode(codeToCref, sb, bestk, config);
        return sb.toString();
    }

    private static Map<ClusterReference, List<ClusterReference>> clusterWithinStatusCode(
            Map<Integer, List<ClusterReference>> codeToCref,
            StringBuilder sb,
            int bestk,
            ClusterConfig config) {
        Distance distance = new ResponseDistance(config);
        Map<ClusterReference, List<ClusterReference>> clusters = new HashMap<>();
        for (Map.Entry<Integer, List<ClusterReference>> statusBasedCluster :
                codeToCref.entrySet()) {
            Map<ClusterReference, List<ClusterReference>> result =
                    KMeans.fit(statusBasedCluster.getValue(), bestk, distance, 100);
            for (Map.Entry<ClusterReference, List<ClusterReference>> entry : result.entrySet()) {
                clusters.put(entry.getKey(), entry.getValue());
                sb.append("Centroid, status code:")
                        .append(statusBasedCluster.getKey())
                        .append(entry.getKey())
                        .append("\n");
                List<ClusterReference> crefs = entry.getValue();
                for (ClusterReference cref : crefs) {
                    sb.append(cref).append("\n");
                }
            }
        }
        return clusters;
    }

    private static Map<Integer, List<ClusterReference>> arrangeByStatusCode(
            List<HistoryReference> hrefs) {
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
        maxValues =
                new ClusterReference(
                        maxResponseLength, maxRequestLength, 1, maxResponseTime, "dummy");

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
                codeToCrefs
                        .get(statusCode)
                        .add(new ClusterReference(href, responseTime, responseBody, maxValues));
            } else {
                List<ClusterReference> list = new ArrayList<>();
                list.add(new ClusterReference(href, responseTime, responseBody, maxValues));
                codeToCrefs.put(statusCode, list);
            }
        }
        return codeToCrefs;
    }
}
