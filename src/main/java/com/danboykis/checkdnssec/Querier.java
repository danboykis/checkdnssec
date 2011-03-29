package com.danboykis.checkdnssec;

import org.xbill.DNS.*;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Iterator;

public class Querier {
    public static class Builder {
        private Name name;
        private String nsTarget;
        private Integer port;

        private boolean hasName;
        private boolean hasNSTarget;
        private boolean hasPort;
        public Builder() {}

        public boolean hasZoneName() { return hasName; }
        public boolean hasNSTarget() { return hasNSTarget; }
        public boolean hasPort() { return hasPort; }

        public Builder setZoneName(Name zn) {
            this.name = zn;
            this.hasName = true;
            return this;
        }
        public Builder setNameServer(String ns) {
            this.nsTarget = ns;
            this.hasNSTarget = true;
            return this;
        }

        public Builder setPort(int p) {
            this.port = p;
            hasPort = true;
            return this;
        }

        public Querier build() throws UnknownHostException {
            if( !hasZoneName() ) { throw new IllegalArgumentException("Name must be set!"); }
            if( !hasPort() ) { this.port = 53; }
            if( !hasNSTarget() ) { return new Querier(this.name,this.port); }
            return new Querier(this.name,this.port,this.nsTarget);
        }
    }

    private Name name;
    private String nsTarget = "";
    private int port;
    private SimpleResolver resolver;
    private KeyHolder keyHolder;

    public static Builder newBuilder() {
        return new Builder();
    }

    public void init() throws UnknownHostException {
        if( nsTarget.isEmpty() ) {
            setNsTarget();
        }
        initResolver();
        setDNSKEYs();
    }
    private void initResolver() throws UnknownHostException {
        SimpleResolver res = new SimpleResolver(this.nsTarget);
        res.setEDNS(0, SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, Flags.DO, Collections.EMPTY_LIST);
        res.setTCP(true);
        res.setPort(this.port);
        this.resolver = res;
    }

    private Querier(Name name, int port) throws UnknownHostException {
        this.name = name;
        this.port = port;
        init();
    }
    private Querier(Name name, int port, String nsTarget) throws UnknownHostException {
        this.name = name;
        this.port = port;
        this.nsTarget = nsTarget;
        init();
    }

    public int getPort() { return port; }
    public String getNsTarget() { return nsTarget; }
    public Name getName() { return name; }
    public KeyHolder getKeyHolder() { return keyHolder; }


    public static Message makeQuery(NameTypePair ntp) {
        return Message.newQuery( Record.newRecord(ntp.name,ntp.type,DClass.IN) );
    }
    public RRset[] queryFor(NameTypePair ntp) throws IOException {
        Message response = resolver.send(makeQuery(ntp));
        if( !response.findRRset(ntp.name,ntp.type) ) {
            throw new RuntimeException(String.format("Didn't get any results for NAME=%s, TYPE=%d",ntp.name,ntp.type));
        }

        RRset[] responseSets = response.getSectionRRsets(Section.ANSWER);
        if( responseSets == null || responseSets.length < 1 ) {
            throw new RuntimeException(String.format("Didn't get any results for NAME=%s, TYPE=%d",ntp.name,ntp.type));
        }
        return responseSets;
    }
    public void setDNSKEYs() {
        this.keyHolder = new KeyHolder();
        NameTypePair ntp = NameTypePair.of(this.getName(),Type.DNSKEY);
        try {
            RRset[] dnsKeys = queryFor(ntp);
            for( RRset s : dnsKeys ) {
                Iterator<DNSKEYRecord> i = s.rrs();
                while( i.hasNext() ) {
                    DNSKEYRecord r = i.next();
                    keyHolder.put(r);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public void setNsTarget() {
        Record[] nsRecs = new Lookup(this.getName(),Type.NS,DClass.IN).run();
        if( nsRecs[0].getType() != Type.NS ) {
            throw new RuntimeException("Cannot query for NS record");
        }
        this.nsTarget = ((NSRecord)nsRecs[0]).getTarget().toString();
    }
}
