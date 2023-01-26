package org.zaproxy.addon.clusterator.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

public class KMeans {

    private static final Random random = new Random();

    public static Map<ClusterReference, List<ClusterReference>> fit(List<ClusterReference> crefs,
                                                                    int k,
                                                                    Distance distance,
                                                                    int maxIterations) {

        List<ClusterReference> centroids = randomCentroids(crefs, k);
        Map<ClusterReference, List<ClusterReference>> clusters = new HashMap<>();
        Map<ClusterReference, List<ClusterReference>> lastState = new HashMap<>();

        // iterate for a pre-defined number of times
        for (int i = 0; i < maxIterations; i++) {
            boolean isLastIteration = i == maxIterations - 1;

            // in each iteration we should find the nearest centroid for each record
            for (ClusterReference clusterReference : crefs) {
                ClusterReference centroid = nearestCentroid(clusterReference, centroids, distance);
                assignToCluster(clusters, clusterReference, centroid);
            }

            // if the assignments do not change, then the algorithm terminates
            boolean shouldTerminate = isLastIteration || clusters.equals(lastState);
            lastState = clusters;
            if (shouldTerminate) {
                break;
            }

            // at the end of each iteration we should relocate the centroids
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
            clusterReference.getFields().forEach((key, value) -> {
                // compares the value with the current max and choose the bigger value between them
                maxs.compute(key, (k1, max) -> max == null || value > max ? value : max);

                // compare the value with the current min and choose the smaller value between them
                mins.compute(key, (k1, min) -> min == null || value < min ? value : min);
            });
        }

        Set<String> attributes = crefs.stream()
                .flatMap(e -> e.getFields().keySet().stream())
                .collect(toSet());
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

    private static ClusterReference nearestCentroid(ClusterReference clusterReference, List<ClusterReference> centroids, Distance distance) {
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

    private static void assignToCluster(Map<ClusterReference, List<ClusterReference>> clusters,
                                        ClusterReference current,
                                        ClusterReference centroid) {
        clusters.compute(centroid, (key, list) -> {
            if (list == null) {
                list = new ArrayList<>();
            }
            list.add(current);
            return list;
        });
    }

    private static ClusterReference average(ClusterReference centroid, List<ClusterReference> crefs) {
        if (crefs == null || crefs.isEmpty()) {
            return centroid;
        }//TODO provjera ako je centroid null?
        Map<String, Double> average = centroid.getFields();
        crefs.stream().flatMap(e -> e.getFields().keySet().stream())
                .forEach(k -> average.put(k, 0.0));

        for (ClusterReference clusterReference : crefs) {
            clusterReference.getFields().forEach(
                    (k, v) -> average.compute(k, (k1, currentValue) -> v + currentValue)
            );
        }

        average.forEach((k, v) -> average.put(k, v / crefs.size()));

        return new ClusterReference(average, randomResponseBody(crefs));
    }

    private static List<ClusterReference> relocateCentroids(Map<ClusterReference, List<ClusterReference>> clusters) {
        return clusters.entrySet().stream().map(e -> average(e.getKey(), e.getValue())).collect(toList());
    }


}