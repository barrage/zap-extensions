package org.zaproxy.addon.automation.jobs.internal;

public interface Distance {
    double calculate(ClusterReference crefA, ClusterReference crefB);
}
