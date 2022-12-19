package org.zaproxy.addon.clusterator.internal;

import java.util.Map;

public class ResponseDistance implements Distance {

    //    cosine, gore suma produkata svih znacajki, dolje sqrt(ai)*sqrt(bi)
//    @Override
//    public double calculate(Map<String, Double> f1, Map<String, Double> f2) {
//        double cosine = 0;
//        for (String key : f1.keySet()) {
//            Double ai = f1.get(key);
//            Double bi = f2.get(key);
//            cosine += ai * bi;
//        }
//        double suma = 0;
//        for(Double ai : f1.values()){
//            suma+=Math.pow(ai, 2);
//        }
//        suma = Math.sqrt(suma);
//        cosine/=suma;
//        suma = 0;
//        for(Double bi : f2.values()){
//            suma+=Math.pow(bi, 2);
//        }
//        suma = Math.sqrt(suma);
//        cosine/=suma;
//        return cosine;
//    }

//    osnovna
    @Override
    double calculate(ClusterReference crefA, ClusterReference crefB){
    double sum = 0;
        for (String key : f1.keySet()) {
            Double v1 = f1.get(key);
            Double v2 = f2.get(key);

            if (v1 != null && v2 != null) {
               if(key.equals("payloadLength")){
                    sum += Math.pow(v1 - v2, 2);
                } else {
                    sum += Math.abs(v1 - v2);
                }
            }
        }
        return Math.sqrt(sum);
    }
}