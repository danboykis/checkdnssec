package com.danboykis.checkdnssec;

import org.xbill.DNS.*;

import java.util.Collections;
import java.util.Iterator;

public final class Querier {
    public DNSKEYRecord ksk = null;
    public DNSKEYRecord zsk = null;
    public String ns;

    private void populateNS(Name n) {
        Record[] nsRecs = new Lookup(n,Type.NS,DClass.IN).run();
        if( nsRecs[0].getType() != Type.NS ) {
            throw new RuntimeException("Cannot query for NS record");
        }
        ns = ((NSRecord)nsRecs[0]).getTarget().toString();
    }
    private void populateDNSKEYs(Name n) throws Exception {
        RRset[] dnsKeys = queryFor(NameTypePair.of(n.toString(), Type.DNSKEY));
        if( dnsKeys == null || dnsKeys.length < 1 ) {
            throw new RuntimeException("Cannot get DNSKEYs for zone!");
        }
        for( RRset s : dnsKeys ) {
            Iterator<DNSKEYRecord> i = s.rrs();
            while( i.hasNext() ) {
                DNSKEYRecord r = i.next();
                if( r.getFlags() == 256 ) { zsk = r; }
                if( r.getFlags() == 257 ) { ksk = r; }
            }
        }
        if( ksk == null || zsk == null ) {
            throw new RuntimeException(String.format("Cannot query for DNSKEY records\nZSK:%s\nKSK:%s",zsk,ksk));
        }
    }

    public Querier(Name n,String nsTarget) throws Exception {
        this.ns = nsTarget;
        populateDNSKEYs(n);
    }
    public Querier(Name n) throws Exception {
        populateNS(n);
        populateDNSKEYs(n);
    }

    public RRset[] queryFor(NameTypePair ntp) throws Exception {
        Record r = Record.newRecord(ntp.name, ntp.type, DClass.IN);
        Message query = Message.newQuery(r);
        SimpleResolver res = new SimpleResolver(ns);
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
