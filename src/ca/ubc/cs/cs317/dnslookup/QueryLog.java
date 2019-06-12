package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;

public class QueryLog {

    public InetAddress qServer;
    public DNSQuery qQuery;
    public DNSResponse dnsResp;

    /** Constructor for a QueryLog.
     *
     * @param qQuery        DNSQuery to print.
     * @param qServer
     * @param dnsResponse   DNSResponse of the query.
     */
    public QueryLog(DNSQuery qQuery, InetAddress qServer, DNSResponse dnsResponse) {
        this.qQuery = qQuery;
        this.qServer = qServer;
        this.dnsResp = dnsResponse;
    }

    /** Print the QueryLog.
     */
    public void printThisLog() {
        System.out.println("\n");

        System.out.println("Query ID     " + byte2int(qQuery.queryID) + " " + qQuery.hostName
                + "  " + qQuery.type.toString() + " --> " + qServer.getHostAddress());
        System.out.println("Response ID: " + byte2int(dnsResp.qID )+ " Authoritative = " + dnsResp.isAuth);

        System.out.println("  Answers (" + dnsResp.answers.size() + ")");
        for (ResourceRecord a : dnsResp.answers) {
            printResourceRecord(a, 1);
        }

        System.out.println("  Nameservers (" + dnsResp.nameServers.size() + ")");
        for (ResourceRecord n : dnsResp.nameServers) {
            printResourceRecord(n, 2);
        }

        System.out.println("  Additional Information (" + dnsResp.addInfo.size() + ")");
        for (ResourceRecord ai : dnsResp.addInfo) {
            printResourceRecord(ai, 0);
        }
    }

    /** Verbose print the resource record details.
     *
     * @param record    Resource record to print.
     * @param rtype     Type of response.
     */
    private static void printResourceRecord(ResourceRecord record, int rtype) {
        System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                record.getTTL(),
                record.getType() == RecordType.OTHER ? rtype : record.getType(),
                record.getTextResult());
    }

    /** Converts byte[] to integer.
     *
     * @param b     byte[] to convert.
     * @return      integer value of b.
     */
    private int byte2int(byte[] b){
        int value = 0;
        for (int i = 0; i <=b.length-1; i++)
            value = (value << 8) + (b[i] & 0xFF);
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        QueryLog ql = (QueryLog) o;


        if (!dnsResp.qID.equals(ql.dnsResp.qID)) return false;
        return (qQuery.queryID.equals(ql.qQuery.queryID));
    }

    @Override
    public int hashCode() {
        int result = qQuery.queryID.hashCode();
        result = 31 * result + dnsResp.hashCode();
        return result;
    }
}
