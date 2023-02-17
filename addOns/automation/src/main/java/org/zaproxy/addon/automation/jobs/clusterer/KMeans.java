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

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public class KMeans {

    private static final Random random = new Random();

    public static Map<ClusterReference, List<ClusterReference>> fit(
            List<ClusterReference> crefs, int k, Distance distance, int maxIterations) {
        List<ClusterReference> centroids = randomCentroids(crefs, k);
        Map<ClusterReference, List<ClusterReference>> clusters = new HashMap<>();
        Map<ClusterReference, List<ClusterReference>> lastState = new HashMap<>();
        for (int i = 0; i < maxIterations; i++) {
            boolean isLastIteration = i == maxIterations - 1;
            for (ClusterReference clusterReference : crefs) {
                ClusterReference centroid = nearestCentroid(clusterReference, centroids, distance);
                assignToCluster(clusters, clusterReference, centroid);
            }
            boolean shouldTerminate = isLastIteration || clusters.equals(lastState);
            lastState = clusters;
            if (shouldTerminate) {
                break;
            }
            centroids = relocateCentroids(clusters);
            clusters = new HashMap<>();
        }

        return lastState;
    }

    private static List<ClusterReference> randomCentroids(List<ClusterReference> crefs, int k) {
        List<ClusterReference> centroids = new ArrayList<>();
        Map<String, Double> maxs = new HashMap<>();
        Map<String, Double> mins = new HashMap<>();

        for (ClusterReference clusterReference : crefs) {
            clusterReference
                    .getFields()
                    .forEach(
                            (key, value) -> {
                                maxs.compute(
                                        key, (k1, max) -> max == null || value > max ? value : max);
                                mins.compute(
                                        key, (k1, min) -> min == null || value < min ? value : min);
                            });
        }

        Set<String> attributes =
                crefs.stream().flatMap(e -> e.getFields().keySet().stream()).collect(toSet());
        for (int i = 0; i < k; i++) {
            Map<String, Double> fields = new HashMap<>();
            for (String attribute : attributes) {
                double max = maxs.get(attribute);
                double min = mins.get(attribute);
                fields.put(attribute, random.nextDouble() * (max - min) + min);
            }
            centroids.add(new ClusterReference(fields, randomResponseBody(crefs)));
        }
        return centroids;
    }

    private static String randomResponseBody(List<ClusterReference> crefs) {
        ClusterReference chosen = crefs.get(random.nextInt(crefs.size()));
        return chosen.getResponseBody();
    }

    private static ClusterReference nearestCentroid(
            ClusterReference clusterReference,
            List<ClusterReference> centroids,
            Distance distance) {
        double minimumDistance = Double.MAX_VALUE;
        ClusterReference nearest = null;

        for (ClusterReference centroid : centroids) {
            double currentDistance = distance.calculate(clusterReference, centroid);

            if (currentDistance < minimumDistance) {
                minimumDistance = currentDistance;
                nearest = centroid;
            }
        }
        return nearest;
    }

    private static void assignToCluster(
            Map<ClusterReference, List<ClusterReference>> clusters,
            ClusterReference current,
            ClusterReference centroid) {
        clusters.compute(
                centroid,
                (key, list) -> {
                    if (list == null) {
                        list = new ArrayList<>();
                    }
                    list.add(current);
                    return list;
                });
    }

    private static ClusterReference average(
            ClusterReference centroid, List<ClusterReference> crefs) {
        if (crefs == null || crefs.isEmpty()) {
            return centroid;
        }
        Map<String, Double> average = centroid.getFields();
        crefs.stream()
                .flatMap(e -> e.getFields().keySet().stream())
                .forEach(k -> average.put(k, 0.0));

        for (ClusterReference clusterReference : crefs) {
            clusterReference
                    .getFields()
                    .forEach((k, v) -> average.compute(k, (k1, currentValue) -> v + currentValue));
        }

        average.forEach((k, v) -> average.put(k, v / crefs.size()));

        return new ClusterReference(average, randomResponseBody(crefs));
    }

    private static List<ClusterReference> relocateCentroids(
            Map<ClusterReference, List<ClusterReference>> clusters) {
        return clusters.entrySet().stream()
                .map(e -> average(e.getKey(), e.getValue()))
                .collect(toList());
    }
}
