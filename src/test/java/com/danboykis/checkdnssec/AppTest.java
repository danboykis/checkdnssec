package com.danboykis.checkdnssec;

import com.danboykis.checkdnssec.cli.CliHandler;
import org.junit.Test;
import static org.junit.Assert.*;
import org.xbill.DNS.Type;

public class AppTest
{
    @Test
    public void testApp()
    {
        try {
            String[] a = new String[]{"-z nist.gov.","--ns=ns1.nist.gov.","-p 53","-Dnist.gov.:SOA","-Dnist.gov.:A"};
            Verifier.main(a);
            a = new String[]{"-z nist.gov.","-p 53","-Dnist.gov.:SOA","-Dnist.gov.:A", "-Dnist.gov.:DNSKEY"};
            Verifier.main(a);
            assertTrue(true);
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
    @Test
    public void testCliHandler() {
        String[] a = new String[]{"-z nist.gov.","--ns=ns1.nist.gov.","-p 53","-Dnist.gov.:SOA"};
        try {
            CliHandler cliHandler = new CliHandler(a);

            assertTrue(cliHandler.getQuerier().getName().toString().equals("nist.gov."));
            assertTrue(cliHandler.getQuerier().getPort() == 53);
            assertTrue(cliHandler.getQuerier().getNsTarget().equals("ns1.nist.gov."));

            for( NameTypePair ntp : cliHandler.getNameTypePairs() ) {
                assertTrue(ntp.name.toString().equals("nist.gov."));
                assertTrue(ntp.type == Type.SOA);
            }

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
