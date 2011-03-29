package com.danboykis.checkdnssec.cli;

import com.danboykis.checkdnssec.NameTypePair;
import com.danboykis.checkdnssec.Querier;
import org.apache.commons.cli.*;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CliHandler {

    private Options opts;
    private Querier.Builder querierBuilder;
    private List<NameTypePair> ntps;

    private enum CmdArgs {
        ZONE("z"),
        PORT("p"),
        NS("ns"),
        PAIRS("D");
        private String identifier;
        CmdArgs(String ident) {
            identifier = ident;
        }

        public String toString() {
            return identifier;
        }
    }

    public void setUpOptions() {
        Options options = new Options();
        Option ns = OptionBuilder.withLongOpt(CmdArgs.NS.toString())
                .hasArgs(1)
                .withDescription("Nameserver to query against")
                .create();
        options.addOption(CmdArgs.ZONE.toString(),true,"Name of the zone to query");
        options.addOption(CmdArgs.PORT.toString(),true,"DNS port (default 53)");
        options.addOption(ns);
        Option property  = OptionBuilder.withArgName( "property:value" )
                                .hasArgs(2)
                                .withValueSeparator(':')
                                .withDescription("use value for given property")
                                .create(CmdArgs.PAIRS.toString());
        options.addOption(property);
        opts = options;
    }
    public CliHandler(String[] args) throws ParseException {
        ntps = new ArrayList<NameTypePair>();
        setUpOptions();
        querierBuilder = Querier.newBuilder();
        parse(args);
    }

    public Querier getQuerier() throws UnknownHostException {
        return querierBuilder.build();
    }

    public List<NameTypePair> getNameTypePairs() {
        return ntps;
    }

    private void parse(String[] args) throws ParseException {
        CommandLineParser parser = new PosixParser();
        CommandLine cmd = parser.parse(opts, args);
        if( cmd.hasOption(CmdArgs.ZONE.toString()) ) {
            String name = cmd.getOptionValue(CmdArgs.ZONE.toString()).trim();
            try {
                Name n = new Name(name);
                querierBuilder.setZoneName(n);
            } catch (TextParseException e) {
                System.err.println("Invalid zone name: "+name);
            }
        }
        if( cmd.hasOption(CmdArgs.NS.toString()) ) {
            String name = cmd.getOptionValue(CmdArgs.NS.toString()).trim();
            querierBuilder.setNameServer(name);
        }
        if( cmd.hasOption(CmdArgs.PORT.toString()) ) {
            String port = cmd.getOptionValue(CmdArgs.PORT.toString());
            Integer p = Integer.parseInt(port.trim());
            querierBuilder.setPort(p);
        }
        if( cmd.hasOption(CmdArgs.PAIRS.toString()) ) {
            String[] nts = cmd.getOptionValues(CmdArgs.PAIRS.toString());
            List<String> names = new ArrayList<String>();
            List<Integer> types = new ArrayList<Integer>();
            for( int i=0; i<nts.length; i++ ) {
                if( i % 2 == 0 ) { names.add(nts[i].trim()); }
                if( i % 2 == 1 ) { types.add(Type.value((nts[i].trim()))); }
            }
            Iterator<String> nameItr = names.iterator();
            Iterator<Integer> typeItr = types.iterator();
            while( nameItr.hasNext() && typeItr.hasNext() ) {
                ntps.add(NameTypePair.of(nameItr.next(), typeItr.next()));
            }
        }
    }
}
