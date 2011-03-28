package com.danboykis.checkdnssec;

import org.xbill.DNS.*;

import java.util.*;

public class Verifier
{
    private List<NameTypePair> argPairs;
    private Querier querier;
    public List<NameTypePair> parseArgs(List<String> argsList) {
        List<NameTypePair> args = new ArrayList<NameTypePair>(argsList.size());
        for( String arg : argsList ) {
            String[] ntp = arg.split(":");
            args.add(NameTypePair.of(ntp[0], Type.value(ntp[1])));
        }
        return args;
    }
    public Verifier(String[] args) throws Exception {
        if(args[0].startsWith("NS:")) {
            this.argPairs = parseArgs(Arrays.asList(Arrays.copyOfRange(args,1,args.length)));
            String nsTarget = args[0].split(":")[1];
            querier = new Querier(argPairs.get(0).name,nsTarget);
        }
        else {
            this.argPairs = parseArgs(Arrays.asList(args));
            querier = new Querier(argPairs.get(0).name);
        }
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
        boolean valid = true;
        Iterator<RRSIGRecord> sigs = set.sigs();
        while( sigs.hasNext() ) {
            RRSIGRecord sig = sigs.next();
            if( querier.ksk.getFootprint() == sig.getFootprint() ) {
                valid = valid && isValid(set, querier.ksk, sig);
            }
            else if( querier.zsk.getFootprint() == sig.getFootprint() ) {
                valid = valid && isValid(set, querier.zsk, sig);
            }
            else {
                System.out.println("WARNING RRSIG DOESN'T MATCH KSK OR ZSK!");
                System.out.println(sig);
            }
        }
        return valid;
    }

    public boolean isValid(RRset set, DNSKEYRecord key, RRSIGRecord rrsig) {
        try {
            System.out.println("Verifying: "+set.getName()+" "+Type.string(set.getType()));
            System.out.println("Against: "+rrsig);
            System.out.println("Using: "+key);
            DNSSEC.verify(set,rrsig,key);
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
        System.out.println(v.querier.ksk);
        System.out.println(v.querier.zsk);
        System.out.println(v.querier.ns);
        System.out.println("--------------------------------------");
        if( !v.isValidZone() ) {
            System.out.println("!!ZONE IS NOT VALID!!");
        }
    }

}
