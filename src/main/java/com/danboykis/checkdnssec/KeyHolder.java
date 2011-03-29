package com.danboykis.checkdnssec;

import org.xbill.DNS.DNSKEYRecord;

import java.util.HashMap;
import java.util.Map;

public class KeyHolder {
    private final Map<Integer,DNSKEYRecord> keys = new HashMap<Integer,DNSKEYRecord>();

    public DNSKEYRecord put(DNSKEYRecord k) {
        return keys.put(k.getFootprint(),k);
    }
    public boolean containsKey(int footprint) {
        return keys.containsKey(footprint);
    }
    public DNSKEYRecord get(int footprint) {
        return keys.get(footprint);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        for( DNSKEYRecord k : keys.values() ) {
            sb.append(k).append("\n");
        }
        return sb.toString();
    }
}
