package com.danboykis.checkdnssec;

import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

public final class NameTypePair {
    public final Name name;
    public final int type;
    private NameTypePair(Name n, int t) {
        name = n;
        type = t;
    }
    public static NameTypePair of(String n, int t) {
        try {
            return new NameTypePair(Name.fromString(n),t);
        } catch (TextParseException e) {
            throw new RuntimeException("Improper dns name passed: "+n);
        }
    }
}
