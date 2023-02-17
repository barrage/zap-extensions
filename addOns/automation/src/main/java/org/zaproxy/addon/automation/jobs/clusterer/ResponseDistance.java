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
