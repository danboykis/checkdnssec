package com.danboykis.checkdnssec;

import com.danboykis.checkdnssec.cli.CliHandler;
import org.xbill.DNS.*;

import java.util.Iterator;
import java.util.List;

public class Verifier
{
    List<NameTypePair> argPairs;
    KeyHolder keyHolder;
    Querier querier;

    public Verifier(String[] args) throws Exception {
        CliHandler cliHandler = new CliHandler(args);
        this.querier = cliHandler.getQuerier();
        this.argPairs = cliHandler.getNameTypePairs();
        this.keyHolder = querier.getKeyHolder();
    }

    public boolean isValidZone() {
        for( NameTypePair ntp : argPairs ) {
            if(!isValidRRset(ntp)){ return false; }
        }
        return true;
    }

    public boolean isValidRRset(NameTypePair ntp) {
        try {
            RRset[] sets = querier.queryFor(ntp);
            for( RRset setToVerify : sets ) {
                if( !isValidSet(setToVerify) ) { return false; }
            }
        } catch (Exception e) {
            throw new RuntimeException(String.format("Could not query for NAME=%s, TYPE=%d",ntp.name,ntp.type));
        }
        return true;
    }

    public boolean isValidSet(RRset set) {
        boolean valid = false;
        Iterator<RRSIGRecord> sigs = set.sigs();
        while( sigs.hasNext() ) {
            RRSIGRecord sig = sigs.next();
            if( !keyHolder.containsKey(sig.getFootprint()) ) {
                System.out.println("WARNING RRSIG DOESN'T MATCH ANY KEYS FOUND!");
                System.out.println(sig);
                valid = false;
            }
            else {
                DNSKEYRecord key = keyHolder.get(sig.getFootprint());
                valid = isValid(set,key,sig);
            }
        }
        return valid;
    }

    public boolean isValid(RRset set, DNSKEYRecord key, RRSIGRecord rrsig) {
        try {
            System.out.println("Verifying: "+set.getName()+" "+Type.string(set.getType()));
            System.out.println("Against: "+rrsig);
            System.out.println("Using: "+key);
            DNSSEC.verify(set, rrsig, key);
            System.out.println("VALID");
            System.out.println("--------------------------------------");
            return true;
        } catch (DNSSEC.DNSSECException e) {
            System.out.println("!!NOT VALID!!");
            System.out.println("--------------------------------------");
            return false;
        }
    }

    public static void main( String[] args ) throws Exception {
        Verifier v = new Verifier(args);
        System.out.println(v.keyHolder);
        System.out.println("--------------------------------------");
        if( !v.isValidZone() ) {
            System.out.println("!!ZONE IS NOT VALID!!");
        }
    }

}
