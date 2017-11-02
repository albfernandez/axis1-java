/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.axis.components.net;

import org.apache.axis.utils.Messages;
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.utils.StringUtils;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Hashtable;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * SSL socket factory. It _requires_ a valid RSA key and
 * JSSE. (borrowed code from tomcat)
 * 
 * THIS CODE STILL HAS DEPENDENCIES ON sun.* and com.sun.*
 *
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class JSSESocketFactory extends DefaultSocketFactory implements SecureSocketFactory {

    // This is a a sorted list, if you insert new elements do it orderdered.
    private final static String[] BAD_COUNTRY_2LDS =
        {"ac", "co", "com", "ed", "edu", "go", "gouv", "gov", "info",
            "lg", "ne", "net", "or", "org"};
    
    /** Field sslFactory           */
    protected SSLSocketFactory sslFactory = null;

    /**
     * Constructor JSSESocketFactory
     *
     * @param attributes
     */
    public JSSESocketFactory(Hashtable attributes) {
        super(attributes);
    }

    /**
     * Initialize the SSLSocketFactory
     * @throws IOException
     */ 
    protected void initFactory() throws IOException {
        sslFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
    }
    
    /**
     * creates a secure socket
     *
     * @param host
     * @param port
     * @param otherHeaders
     * @param useFullURL
     *
     * @return Socket
     * @throws Exception
     */
    public Socket create(
            String host, int port, StringBuffer otherHeaders, BooleanHolder useFullURL)
            throws Exception {
        if (sslFactory == null) {
            initFactory();
        }
        if (port == -1) {
            port = 443;
        }

        TransportClientProperties tcp = TransportClientPropertiesFactory.create("https");

        boolean hostInNonProxyList = isHostInNonProxyList(host, tcp.getNonProxyHosts());

        Socket sslSocket = null;
        if (tcp.getProxyHost().length() == 0 || hostInNonProxyList) {
            // direct SSL connection
            sslSocket = sslFactory.createSocket(host, port);
        } else {

            // Default proxy port is 80, even for https
            int tunnelPort = (tcp.getProxyPort().length() != 0)
                             ? Integer.parseInt(tcp.getProxyPort())
                             : 80;
            if (tunnelPort < 0)
                tunnelPort = 80;

            // Create the regular socket connection to the proxy
            Socket tunnel = new Socket(tcp.getProxyHost(), tunnelPort);

            // The tunnel handshake method (condensed and made reflexive)
            OutputStream tunnelOutputStream = tunnel.getOutputStream();
            PrintWriter out = new PrintWriter(
                    new BufferedWriter(new OutputStreamWriter(tunnelOutputStream)));

            // More secure version... engage later?
            // PasswordAuthentication pa =
            // Authenticator.requestPasswordAuthentication(
            // InetAddress.getByName(tunnelHost),
            // tunnelPort, "SOCK", "Proxy","HTTP");
            // if(pa == null){
            // printDebug("No Authenticator set.");
            // }else{
            // printDebug("Using Authenticator.");
            // tunnelUser = pa.getUserName();
            // tunnelPassword = new String(pa.getPassword());
            // }
            out.print("CONNECT " + host + ":" + port + " HTTP/1.0\r\n"
                    + "User-Agent: AxisClient");
            if (tcp.getProxyUser().length() != 0 &&
                tcp.getProxyPassword().length() != 0) {

                // add basic authentication header for the proxy
                String encodedPassword = XMLUtils.base64encode((tcp.getProxyUser()
                        + ":"
                        + tcp.getProxyPassword()).getBytes());

                out.print("\nProxy-Authorization: Basic " + encodedPassword);
            }
            out.print("\nContent-Length: 0");
            out.print("\nPragma: no-cache");
            out.print("\r\n\r\n");
            out.flush();
            InputStream tunnelInputStream = tunnel.getInputStream();

            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("isNull00", "tunnelInputStream",
                        "" + (tunnelInputStream
                        == null)));
            }
            String replyStr = "";

            // Make sure to read all the response from the proxy to prevent SSL negotiation failure
            // Response message terminated by two sequential newlines
            int newlinesSeen = 0;
            boolean headerDone = false;    /* Done on first newline */

            while (newlinesSeen < 2) {
                int i = tunnelInputStream.read();

                if (i < 0) {
                    throw new IOException("Unexpected EOF from proxy");
                }
                if (i == '\n') {
                    headerDone = true;
                    ++newlinesSeen;
                } else if (i != '\r') {
                    newlinesSeen = 0;
                    if (!headerDone) {
                        replyStr += String.valueOf((char) i);
                    }
                }
            }
            if (StringUtils.startsWithIgnoreWhitespaces("HTTP/1.0 200", replyStr) &&
                    StringUtils.startsWithIgnoreWhitespaces("HTTP/1.1 200", replyStr)) {
                throw new IOException(Messages.getMessage("cantTunnel00",
                        new String[]{
                            tcp.getProxyHost(),
                            "" + tunnelPort,
                            replyStr}));
            }

            // End of condensed reflective tunnel handshake method
            sslSocket = sslFactory.createSocket(tunnel, host, port, true);
            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("setupTunnel00",
                          tcp.getProxyHost(),
                        "" + tunnelPort));
            }
        }

        ((SSLSocket) sslSocket).startHandshake();
        if (log.isDebugEnabled()) {
            log.debug(Messages.getMessage("createdSSL00"));
        }
        verifyHostName(host, (SSLSocket) sslSocket);
        return sslSocket;
    }

    /**
     * Verifies that the given hostname in certicifate is the hostname we are trying to connect to
     * http://www.cvedetails.com/cve/CVE-2012-5784/
     * @param host
     * @param ssl
     * @throws IOException
     */
    
	private static void verifyHostName(String host, SSLSocket ssl)
			throws IOException {
		if (host == null) {
			throw new IllegalArgumentException("host to verify was null");
		}

		SSLSession session = ssl.getSession();
		if (session == null) {
            // In our experience this only happens under IBM 1.4.x when
            // spurious (unrelated) certificates show up in the server's chain.
            // Hopefully this will unearth the real problem:
			InputStream in = ssl.getInputStream();
			in.available();
            /*
                 If you're looking at the 2 lines of code above because you're
                 running into a problem, you probably have two options:

                    #1.  Clean up the certificate chain that your server
                         is presenting (e.g. edit "/etc/apache2/server.crt" or
                         wherever it is your server's certificate chain is
                         defined).

                                             OR

                    #2.   Upgrade to an IBM 1.5.x or greater JVM, or switch to a
                          non-IBM JVM.
              */

            // If ssl.getInputStream().available() didn't cause an exception,
            // maybe at least now the session is available?
			session = ssl.getSession();
			if (session == null) {
                // If it's still null, probably a startHandshake() will
                // unearth the real problem.
				ssl.startHandshake();

                // Okay, if we still haven't managed to cause an exception,
                // might as well go for the NPE.  Or maybe we're okay now?
				session = ssl.getSession();
			}
		}

		Certificate[] certs = session.getPeerCertificates();
		verifyHostName(host.trim().toLowerCase(Locale.US),  (X509Certificate) certs[0]);
	}
	/**
	 * Extract the names from the certificate and tests host matches one of them
	 * @param host
	 * @param cert
	 * @throws SSLException
	 */

	private static void verifyHostName(final String host, X509Certificate cert)
			throws SSLException {
        // I'm okay with being case-insensitive when comparing the host we used
        // to establish the socket to the hostname in the certificate.
        // Don't trim the CN, though.
        
		String cn = getCN(cert);
		String[] subjectAlts = getDNSSubjectAlts(cert);
		verifyHostName(host, cn.toLowerCase(Locale.US), subjectAlts);

	}

	/**
	 * Extract all alternative names from a certificate.
	 * @param cert
	 * @return
	 */
	private static String[] getDNSSubjectAlts(X509Certificate cert) {
		LinkedList subjectAltList = new LinkedList();
		Collection c = null;
		try {
			c = cert.getSubjectAlternativeNames();
		} catch (CertificateParsingException cpe) {
			// Should probably log.debug() this?
			cpe.printStackTrace();
		}
		if (c != null) {
			Iterator it = c.iterator();
			while (it.hasNext()) {
				List list = (List) it.next();
				int type = ((Integer) list.get(0)).intValue();
				// If type is 2, then we've got a dNSName
				if (type == 2) {
					String s = (String) list.get(1);
					subjectAltList.add(s);
				}
			}
		}
		if (!subjectAltList.isEmpty()) {
			String[] subjectAlts = new String[subjectAltList.size()];
			subjectAltList.toArray(subjectAlts);
			return subjectAlts;
		} else {
			return new String[0];
		}
	        
	}
	/**
	 * Verifies
	 * @param host
	 * @param cn
	 * @param subjectAlts
	 * @throws SSLException
	 */

	private static void verifyHostName(final String host, String cn, String[] subjectAlts)throws SSLException{
		StringBuffer cnTested = new StringBuffer();

		for (int i = 0; i < subjectAlts.length; i++){
			String name = subjectAlts[i];
			if (name != null) {
				name = name.toLowerCase();
				if (verifyHostName(host, name)){
					return;
				}
				cnTested.append("/").append(name);
			}				
		}
		if (cn != null && verifyHostName(host, cn)){
			return;
		}
		cnTested.append("/").append(cn);
		throw new SSLException("hostname in certificate didn't match: <"
					+ host + "> != <" + cnTested + ">");
		
	}		
	
	private static boolean verifyHostName(final String host, final String cn){
		if (doWildCard(cn) && !isIPAddress(host)) {
			return matchesWildCard(cn, host);
		} 
		return host.equalsIgnoreCase(cn);		
	}
    private static boolean doWildCard(String cn) {
		// Contains a wildcard
		// wildcard in the first block
    	// not an ipaddress (ip addres must explicitily be equal)
    	// not using 2nd level common tld : ex: not for *.co.uk
    	String parts[] = cn.split("\\.");
    	return parts.length >= 3 &&
    			parts[0].endsWith("*") &&
    			acceptableCountryWildcard(cn) &&
    			!isIPAddress(cn);
    }
    
    
	private static final Pattern IPV4_PATTERN = 
			Pattern.compile("^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$");

	private static final Pattern IPV6_STD_PATTERN = 
			Pattern.compile("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");

	private static final Pattern IPV6_HEX_COMPRESSED_PATTERN = 
			Pattern.compile("^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$");


	private static boolean isIPAddress(final String hostname) {
		return hostname != null
				&& (
						IPV4_PATTERN.matcher(hostname).matches()
						|| IPV6_STD_PATTERN.matcher(hostname).matches() 
						|| IPV6_HEX_COMPRESSED_PATTERN.matcher(hostname).matches()
		);

	}

	private static boolean acceptableCountryWildcard(final String cn) {
		// The CN better have at least two dots if it wants wildcard action,
		// but can't be [*.co.uk] or [*.co.jp] or [*.org.uk], etc...
		// The [*.co.uk] problem is an interesting one. Should we just
		// hope that CA's would never foolishly allow such a
		// certificate to happen?
    	
		String[] parts = cn.split("\\.");
		// Only checks for 3 levels, with country code of 2 letters.
		if (parts.length > 3 || parts[parts.length - 1].length() != 2) {
			return true;
		}
		String countryCode = parts[parts.length - 2];
		return Arrays.binarySearch(BAD_COUNTRY_2LDS, countryCode) < 0;
	}

	private static boolean matchesWildCard(final String cn,
			final String hostName) {
		String parts[] = cn.split("\\.");
		boolean match = false;
		String firstpart = parts[0];
		if (firstpart.length() > 1) {
			// server∗
			// e.g. server
			String prefix =  firstpart.substring(0, firstpart.length() - 1);
			// skipwildcard part from cn
			String suffix = cn.substring(firstpart.length()); 
			// skip wildcard part from host
			String hostSuffix = hostName.substring(prefix.length());			
			match = hostName.startsWith(prefix) && hostSuffix.endsWith(suffix);
		} else {
			match = hostName.endsWith(cn.substring(1));
		}
		if (match) {
			// I f we're in strict mode ,
			// [ ∗.foo.com] is not allowed to match [a.b.foo.com]
			match = countDots(hostName) == countDots(cn);
		}
		return match;
	}

	private static int countDots(final String data) {
		int dots = 0;
		for (int i = 0; i < data.length(); i++) {
			if (data.charAt(i) == '.') {
				dots += 1;
			}
		}
		return dots;
	}

    private static String getCN(final X509Certificate cert) {
        final String subjectPrincipal = cert.getSubjectX500Principal().toString();
        try {
            return extractCN(subjectPrincipal);
        } catch (SSLException ex) {
            return null;
        }
    }

    private static String extractCN(final String subjectPrincipal) throws SSLException {
        if (subjectPrincipal == null) {
            return null;
        }
        try {
            DNParser dnp = new DNParser(subjectPrincipal);
            // return null or actual CN value
            return dnp.find("cn");
        } catch (IOException e) {
            throw new SSLException(subjectPrincipal + " is not a valid X500 distinguished name");
        }
    }

    /*
     * Taken from Android project:
     * https://platform--frameworks--base.android-source-browsing.googlecode.com/git-history/e46145f7c114b9ac6d19c6a7886e9239463f91e1/common/java/com/android/common/DNParser.java
     * Licensed under ASL 2.0
     */

    /*
     *  Licensed to the Apache Software Foundation (ASF) under one or more
     *  contributor license agreements.  See the NOTICE file distributed with
     *  this work for additional information regarding copyright ownership.
     *  The ASF licenses this file to You under the Apache License, Version 2.0
     *  (the "License"); you may not use this file except in compliance with
     *  the License.  You may obtain a copy of the License at
     *
     *     http://www.apache.org/licenses/LICENSE-2.0
     *
     *  Unless required by applicable law or agreed to in writing, software
     *  distributed under the License is distributed on an "AS IS" BASIS,
     *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     *  See the License for the specific language governing permissions and
     *  limitations under the License.
     */

    /*
     * A simple distinguished name(DN) parser.
     *
     * <p>This class is based on org.apache.harmony.security.x509.DNParser.  It's customized to remove
     * external references which are unnecessary for our requirements.
     *
     * <p>This class is only meant for extracting a string value from a DN.  e.g. it doesn't support
     * values in the hex-string style.
     */
    private static final class DNParser {
        /** DN to be parsed. */
        private final String dn;

        // length of distinguished name string
        private final int length;

        private int pos, beg, end;

        // tmp vars to store positions of the currently parsed item
        private int cur;

        // distinguished name chars
        private char[] chars;

        /*
         * Exception message thrown when we failed to parse DN
         */
        private static final String ERROR_PARSE_ERROR = "Failed to parse DN";

        /*
         * Constructor.
         *
         * @param principal
         *            - {@link java.lang.String} to be parsed
         */
        public DNParser(String principal) {
            this.dn = principal;
            this.length = dn.length();
        }

        // gets next attribute type: (ALPHA 1*keychar) / oid
        private String nextAT() throws IOException {

            // skip preceding space chars, they can present after
            // comma or semicolon (compatibility with RFC 1779)
            for (; pos < length && chars[pos] == ' '; pos++) {
            }
            if (pos == length) {
                return null; // reached the end of DN
            }

            // mark the beginning of attribute type
            beg = pos;

            // attribute type chars
            pos++;
            for (; pos < length && chars[pos] != '=' && chars[pos] != ' '; pos++) {
                // we don't follow exact BNF syntax here:
                // accept any char except space and '='
            }
            if (pos >= length) {
                // unexpected end of DN
                throw new IOException(ERROR_PARSE_ERROR);
            }

            // mark the end of attribute type
            end = pos;

            // skip trailing space chars between attribute type and '='
            // (compatibility with RFC 1779)
            if (chars[pos] == ' ') {
                for (; pos < length && chars[pos] != '=' && chars[pos] == ' '; pos++) {
                }

                if (chars[pos] != '=' || pos == length) {
                    // unexpected end of DN
                    throw new IOException(ERROR_PARSE_ERROR);
                }
            }

            pos++; // skip '=' char

            // skip space chars between '=' and attribute value
            // (compatibility with RFC 1779)
            for (; pos < length && chars[pos] == ' '; pos++) {
            }

            // in case of oid attribute type skip its prefix: "oid." or "OID."
            // (compatibility with RFC 1779)
            if ((end - beg > 4) && (chars[beg + 3] == '.')
                    && (chars[beg] == 'O' || chars[beg] == 'o')
                    && (chars[beg + 1] == 'I' || chars[beg + 1] == 'i')
                    && (chars[beg + 2] == 'D' || chars[beg + 2] == 'd')) {
                beg += 4;
            }

            return new String(chars, beg, end - beg);
        }

        // gets quoted attribute value: QUOTATION *( quotechar / pair )
        // QUOTATION
        private String quotedAV() throws IOException {

            pos++;
            beg = pos;
            end = beg;
            while (true) {

                if (pos == length) {
                    // unexpected end of DN
                    throw new IOException(ERROR_PARSE_ERROR);
                }

                if (chars[pos] == '"') {
                    // enclosing quotation was found
                    pos++;
                    break;
                } else if (chars[pos] == '\\') {
                    chars[end] = getEscaped();
                } else {
                    // shift char: required for string with escaped chars
                    chars[end] = chars[pos];
                }
                pos++;
                end++;
            }

            // skip trailing space chars before comma or semicolon.
            // (compatibility with RFC 1779)
            for (; pos < length && chars[pos] == ' '; pos++) {
            }

            return new String(chars, beg, end - beg);
        }

        // gets hex string attribute value: "#" hexstring
        private String hexAV() throws IOException {

            if (pos + 4 >= length) {
                // encoded byte array must be not less then 4 c
                throw new IOException(ERROR_PARSE_ERROR);
            }

            beg = pos; // store '#' position
            pos++;
            while (true) {

                // check for end of attribute value
                // looks for space and component separators
                if (pos == length || chars[pos] == '+' || chars[pos] == ','
                        || chars[pos] == ';') {
                    end = pos;
                    break;
                }

                if (chars[pos] == ' ') {
                    end = pos;
                    pos++;
                    // skip trailing space chars before comma or semicolon.
                    // (compatibility with RFC 1779)
                    for (; pos < length && chars[pos] == ' '; pos++) {
                    }
                    break;
                } else if (chars[pos] >= 'A' && chars[pos] <= 'F') {
                    chars[pos] += 32; // to low case
                }

                pos++;
            }

            // verify length of hex string
            // encoded byte array must be not less then 4 and must be even
            // number
            int hexLen = end - beg; // skip first '#' char
            if (hexLen < 5 || (hexLen & 1) == 0) {
                throw new IOException(ERROR_PARSE_ERROR);
            }

            // get byte encoding from string representation
            byte[] encoded = new byte[hexLen / 2];
            for (int i = 0, p = beg + 1; i < encoded.length; p += 2, i++) {
                encoded[i] = (byte) getByte(p);
            }

            return new String(chars, beg, hexLen);
        }

        // gets string attribute value: *( stringchar / pair )
        private String escapedAV() throws IOException {

            beg = pos;
            end = pos;
            while (true) {

                if (pos >= length) {
                    // the end of DN has been found
                    return new String(chars, beg, end - beg);
                }

                switch (chars[pos]) {
                case '+':
                case ',':
                case ';':
                    // separator char has beed found
                    return new String(chars, beg, end - beg);
                case '\\':
                    // escaped char
                    chars[end++] = getEscaped();
                    pos++;
                    break;
                case ' ':
                    // need to figure out whether space defines
                    // the end of attribute value or not
                    cur = end;

                    pos++;
                    chars[end++] = ' ';

                    for (; pos < length && chars[pos] == ' '; pos++) {
                        chars[end++] = ' ';
                    }
                    if (pos == length || chars[pos] == ',' || chars[pos] == '+'
                            || chars[pos] == ';') {
                        // separator char or the end of DN has beed found
                        return new String(chars, beg, cur - beg);
                    }
                    break;
                default:
                    chars[end++] = chars[pos];
                    pos++;
                }
            }
        }

        // returns escaped char
        private char getEscaped() throws IOException {

            pos++;
            if (pos == length) {
                throw new IOException(ERROR_PARSE_ERROR);
            }

            switch (chars[pos]) {
            case '"':
            case '\\':
            case ',':
            case '=':
            case '+':
            case '<':
            case '>':
            case '#':
            case ';':
            case ' ':
            case '*':
            case '%':
            case '_':
                // FIXME: escaping is allowed only for leading or trailing space
                // char
                return chars[pos];
            default:
                // RFC doesn't explicitly say that escaped hex pair is
                // interpreted as UTF-8 char. It only contains an example of
                // such DN.
                return getUTF8();
            }
        }

        // decodes UTF-8 char
        // see http://www.unicode.org for UTF-8 bit distribution table
        private char getUTF8() throws IOException {

            int res = getByte(pos);
            pos++; // FIXME tmp

            if (res < 128) { // one byte: 0-7F
                return (char) res;
            } else if (res >= 192 && res <= 247) {

                int count;
                if (res <= 223) { // two bytes: C0-DF
                    count = 1;
                    res = res & 0x1F;
                } else if (res <= 239) { // three bytes: E0-EF
                    count = 2;
                    res = res & 0x0F;
                } else { // four bytes: F0-F7
                    count = 3;
                    res = res & 0x07;
                }

                int b;
                for (int i = 0; i < count; i++) {
                    pos++;
                    if (pos == length || chars[pos] != '\\') {
                        return 0x3F; // FIXME failed to decode UTF-8 char -
                                     // return '?'
                    }
                    pos++;

                    b = getByte(pos);
                    pos++; // FIXME tmp
                    if ((b & 0xC0) != 0x80) {
                        return 0x3F; // FIXME failed to decode UTF-8 char -
                                     // return '?'
                    }

                    res = (res << 6) + (b & 0x3F);
                }
                return (char) res;
            } else {
                return 0x3F; // FIXME failed to decode UTF-8 char - return '?'
            }
        }

        // Returns byte representation of a char pair
        // The char pair is composed of DN char in
        // specified 'position' and the next char
        // According to BNF syntax:
        // hexchar = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
        // / "a" / "b" / "c" / "d" / "e" / "f"
        private int getByte(int position) throws IOException {

            if ((position + 1) >= length) {
                // to avoid ArrayIndexOutOfBoundsException
                throw new IOException(ERROR_PARSE_ERROR);
            }

            int b1, b2;

            b1 = chars[position];
            if (b1 >= '0' && b1 <= '9') {
                b1 = b1 - '0';
            } else if (b1 >= 'a' && b1 <= 'f') {
                b1 = b1 - 87; // 87 = 'a' - 10
            } else if (b1 >= 'A' && b1 <= 'F') {
                b1 = b1 - 55; // 55 = 'A' - 10
            } else {
                throw new IOException(ERROR_PARSE_ERROR);
            }

            b2 = chars[position + 1];
            if (b2 >= '0' && b2 <= '9') {
                b2 = b2 - '0';
            } else if (b2 >= 'a' && b2 <= 'f') {
                b2 = b2 - 87; // 87 = 'a' - 10
            } else if (b2 >= 'A' && b2 <= 'F') {
                b2 = b2 - 55; // 55 = 'A' - 10
            } else {
                throw new IOException(ERROR_PARSE_ERROR);
            }

            return (b1 << 4) + b2;
        }

        /*
         * Parses the DN and returns the attribute value for an attribute type.
         *
         * @param attributeType
         *            attribute type to look for (e.g. "ca")
         * @return value of the attribute that first found, or null if none
         *         found
         * @throws IOException
         */
        public String find(String attributeType) throws IOException {

            // Initialize internal state.
            pos = 0;
            beg = 0;
            end = 0;
            cur = 0;
            chars = dn.toCharArray();

            String attType = nextAT();
            if (attType == null) {
                return null;
            }
            while (true) {
                String attValue = "";

                if (pos == length) {
                    return null;
                }

                switch (chars[pos]) {
                case '"':
                    attValue = quotedAV();
                    break;
                case '#':
                    attValue = hexAV();
                    break;
                case '+':
                case ',':
                case ';': // compatibility with RFC 1779: semicolon can separate
                          // RDNs
                    // empty attribute value
                    break;
                default:
                    attValue = escapedAV();
                }

                if (attributeType.equalsIgnoreCase(attType)) {
                    return attValue;
                }

                if (pos >= length) {
                    return null;
                }

                if (chars[pos] == ',' || chars[pos] == ';') {
                } else if (chars[pos] != '+') {
                    throw new IOException(ERROR_PARSE_ERROR);
                }

                pos++;
                attType = nextAT();
                if (attType == null) {
                    throw new IOException(ERROR_PARSE_ERROR);
                }
            }
        }
    }
}
