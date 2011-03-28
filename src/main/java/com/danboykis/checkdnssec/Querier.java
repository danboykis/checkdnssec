package com.danboykis.checkdnssec;

import org.xbill.DNS.*;

import java.util.Collections;

public final class Querier {
    public DNSKEYRecord ksk = null;
    public DNSKEYRecord zsk = null;
    public NSRecord ns;

    private void populateNS(Name n) {
        Record[] nsRecs = new Lookup(n,Type.NS,DClass.IN).run();
        if( nsRecs[0].getType() != Type.NS ) {
            throw new RuntimeException("Cannot query for NS record");
        }
        ns = (NSRecord)nsRecs[0];
    }
    private void populateDNSKEYs(Name n) {
        Record[] dnsRecs = new Lookup(n,Type.DNSKEY,DClass.IN).run();
        for( Record r : dnsRecs ) {
            if( r.getType() == Type.DNSKEY ) {
                DNSKEYRecord k = (DNSKEYRecord)r;
                if( k.getFlags() == 256 ) { zsk = k; }
                if( k.getFlags() == 257 ) { ksk = k; }
            }
        }
        if( ksk == null || zsk == null ) {
            throw new RuntimeException(String.format("Cannot query for DNSKEY records\nZSK:%s\nKSK:%s",zsk,ksk));
        }
    }

    public Querier(Name n,Name nsTarget) {
        populateDNSKEYs(n);
        this.ns = new NSRecord(n,DClass.IN,86400L,nsTarget);
    }
    public Querier(Name n) {
        populateNS(n);
        populateDNSKEYs(n);
    }

    public RRset[] queryFor(NameTypePair ntp) throws Exception {
        Record r = Record.newRecord(ntp.name, ntp.type, DClass.IN);
        Message query = Message.newQuery(r);
        SimpleResolver res = new SimpleResolver(ns.getTarget().toString());
        res.setEDNS(0,SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE,Flags.DO, Collections.EMPTY_LIST);
        res.setTCP(true);
        Message response = res.send(query);
        if( !response.findRRset(ntp.name,ntp.type) ) {
            throw new RuntimeException(String.format("Didn't get any results for NAME=%s, TYPE=%d",ntp.name,ntp.type));
        }

        RRset[] setsToVerify = response.getSectionRRsets(Section.ANSWER);
        return setsToVerify;
    }
}
