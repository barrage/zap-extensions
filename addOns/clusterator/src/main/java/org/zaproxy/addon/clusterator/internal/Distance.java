package org.zaproxy.addon.clusterator.internal;

import java.util.Map;

public interface Distance {
    double calculate(ClusterReference crefA, ClusterReference crefB);
}
