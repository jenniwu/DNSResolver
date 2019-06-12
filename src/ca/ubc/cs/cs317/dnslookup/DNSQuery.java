package ca.ubc.cs.cs317.dnslookup;


import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

public class DNSQuery {

    public String hostName;
    public ByteArrayOutputStream queryInBytes;
    public RecordType type;
    public byte[] queryID;
    public byte[] queryFlags;
    public byte[] responseFlags;
    public byte[] qdCount;
    public byte[] anCount;
    public byte[] nsCount;
    public byte[] arCount;
    public byte[] qType;
    public byte[] qClass;

    /** Constructor for a DNSQuery.
     *
     * @param node  The node for the DNSQuery.
     */
    public DNSQuery(DNSNode node) {
        this.hostName = node.getHostName();
        queryInBytes = new ByteArrayOutputStream();
        type = node.getType();
        queryID = new byte[2];
        queryFlags = new byte[1];
        responseFlags = new byte[1];
        qdCount = new byte[2];
        anCount = new byte[2];
        nsCount = new byte[2];
        arCount = new byte[2];
        qType = new byte[2];
        qClass = new byte[2];
    }

    /** Sets queryID to be a byte[] of the id, and sets the queryIDinInt to be the id.
     *
     * @param id    The queryID.
     */
    public void setQueryID(int id) {
        byte[] buf = ByteBuffer.allocate(4).putInt(id).array();
        queryID[0] = buf[2];
        queryID[1] = buf[3];
    }

    public byte[] getQueryInBytes() {
        encodeQuery();
        return queryInBytes.toByteArray();
    }

    /** Adds the length octet (domain label specification) to the front of label.
     *
     * @param label     A part of a domain name.
     * @return          A label with length octet appended to the front.
     */
    private static byte[] getDomainLabelSpec(byte[] label) {
        int len = label.length;

        ByteArrayOutputStream res = new ByteArrayOutputStream();
        res.write(len);
        res.write(label, 0, len);

        return res.toByteArray();
    }


    /**
     * Formats appropriate DNSQuery appropriately.
     */
    private void encodeQuery() {
        // setting DNS query ID
        queryInBytes.write(queryID,0, queryID.length);

        queryFlags[0] = 0;   // setting DNS query flags
        queryInBytes.write(queryFlags,0, queryFlags.length);

        responseFlags[0] = 0;   // setting DNS response flags
        queryInBytes.write(responseFlags,0, responseFlags.length);

        qdCount[1]=1;
        queryInBytes.write(qdCount,0, qdCount.length);
        queryInBytes.write(anCount,0, anCount.length);
        queryInBytes.write(nsCount,0, nsCount.length);
        queryInBytes.write(arCount,0, arCount.length);

        // write bytes of QNAME to queryInBytes
        String[] labels = hostName.split("\\.");
        for (int i = 0; i < labels.length; i++) {
            byte[] buf = getDomainLabelSpec(labels[i].getBytes());
            queryInBytes.write(buf, 0, buf.length);
        }
        queryInBytes.write(0);// 0 byte at the end of QNAME

        // write bytes of QTYPE to queryInBytes
        byte[] typeCode = ByteBuffer.allocate(4).putInt(type.getCode()).array();
        qType[0] = typeCode[2];
        qType[1] = typeCode[3];
        queryInBytes.write(qType, 0, qType.length);

        // write QCLASS to queryInBytes
        qClass[1]=1;
        queryInBytes.write(qClass,0, qClass.length);
    }
}