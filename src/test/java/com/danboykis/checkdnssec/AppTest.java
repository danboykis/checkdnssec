package com.danboykis.checkdnssec;

import junit.framework.TestCase;

public class AppTest  extends TestCase
{
    public void testApp() throws Exception
    {
        String[] a = new String[]{"NS:ns1.nist.gov.","nist.gov.:A","nist.gov.:MX","nist.gov.:SOA"};
        Verifier.main(a);
        assertTrue(true);
    }
}
