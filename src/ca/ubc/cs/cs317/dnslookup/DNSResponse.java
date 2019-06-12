package ca.ubc.cs.cs317.dnslookup;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.util.*;

public class DNSResponse {
    private byte[] rawBytes;
    private int pointer;

    public byte[] qID;
    public byte[] Flags;
    public boolean isAuth;
    public byte[] Error;
    public int qdCount;
    public int anCount;
    public int nsCount;
    public int arCount;
    public String qName;
    public RecordType qType;
    public byte[] qClass;
    private static DNSCache cache = DNSCache.getInstance();

    public Set<DNSNode> authoratitiveNS;
    public List<ResourceRecord> answers;
    public List<ResourceRecord> nameServers;
    public List<ResourceRecord> addInfo;

    /** Constructor for DNSResponse.
     *
     * @param rawBytes  Data from the datagram received.
     */
    public DNSResponse(byte[] rawBytes) {
        this.rawBytes = rawBytes;
        authoratitiveNS = new HashSet<>();
        answers = new ArrayList<>();
        nameServers = new ArrayList<>();
        addInfo = new ArrayList<>();
        pointer = 0;
        parseBegining();
    }

    /** Parse the querying section of the DNS response.
     */
    private void parseBegining(){
        qID = getSubArrayFromRaw(0, 2);
        Flags = getSubArrayFromRaw(2, 3);
        isAuth = toBinary(Flags).substring(5,6).equals("1");
        Error = getSubArrayFromRaw(3, 4);
        qdCount = byte2int(getSubArrayFromRaw(4, 6));
        anCount = byte2int(getSubArrayFromRaw(6, 8));
        nsCount = byte2int(getSubArrayFromRaw(8, 10));
        arCount = byte2int(getSubArrayFromRaw(10,12));
        qName = getqName(12,false);
        qType = getType();
        qClass = getSubArrayFromRaw(pointer, pointer+2);
        pointer += 2;
    }

    /** Add resource records returned in the response to the cache.
     */
    public void cacheResourceRecords(){
        for(int i = 0; i < anCount+nsCount+arCount; i++){
            String name = getqName(pointer,false);
            RecordType type = getType();
            pointer += 2;   //skip QCLASS
            int TTL = getTTL();

            int DataLength = byte2int(getSubArrayFromRaw(pointer, pointer+2));
            pointer += 2;

            String textResult;
            InetAddress inetResult;
            ResourceRecord rr;

            switch(type) {
                case NS:
                    textResult=getqName(pointer,false);
                    rr = new ResourceRecord(name, type, TTL, textResult);
                    cache.addResult(rr);
                    authoratitiveNS.add(new DNSNode(textResult, type));
                    addToLists(i, rr);
                    break;
                case CNAME:
                    textResult = getqName(pointer,false);
                    rr = new ResourceRecord(name, type, TTL, textResult);
                    cache.addResult(rr);
                    addToLists(i, rr);
                    break;
                case A:
                    try {
                        inetResult = InetAddress.getByAddress(getSubArrayFromRaw(pointer, pointer+DataLength));
                        pointer += DataLength;
                        rr = new ResourceRecord(name, type, TTL, inetResult);
                        cache.addResult(rr);
                        addToLists(i, rr);
                    }
                    catch (Exception e) {} //ignore exception and proceed
                    break;
                case AAAA:
                    try{
                        inetResult = InetAddress.getByAddress(getSubArrayFromRaw(pointer, pointer+DataLength));
                        pointer += DataLength;
                        rr = new ResourceRecord(name, type, TTL, inetResult);
                        cache.addResult(rr);
                        addToLists(i, rr);
                    }
                    catch (Exception e) {} //ignore exception and proceed
                    break;
                default:
                    textResult = getqName(pointer,false);
                    rr = new ResourceRecord(name, type, TTL, textResult);
                    cache.addResult(rr);
                    addToLists(i, rr);
                    break;
            }


        }
    }

    /** Get the bytes between from and to in the rawBytes byte[].
     *
     * @param from  Beginning of new byte[] (inclusive).
     * @param to    End of new byte[] (exclusive).
     * @return      A new byte[] with everything in between from and to.
     */
    private byte[] getSubArrayFromRaw(int from, int to){
        return Arrays.copyOfRange(rawBytes, from, to);
    }

    /** Gets the QNAME in a String.
     *
     * @param StartPosition Beginning of the QNAME.
     * @param isRecursion   Flag for recursive call.
     * @return              QNAME Address.
     */
    private String getqName(int StartPosition, boolean isRecursion) {
        int currPos = StartPosition;
        int namePointer;
        int currLen = 0;
        String name = new String();

        while (rawBytes[currPos] != 0) {
            currLen = byte2int(getSubArrayFromRaw(currPos, currPos+1));

            //Detect a compression and recurse on that destination
            if (currLen >= 64) {
                namePointer = byte2int(getSubArrayFromRaw(currPos, currPos+2)) - 0xc000;
                name += getqName(namePointer,true);
                if (!isRecursion)
                    pointer += 2;
                return name;
            } else {
                for (int i = 1; i <= currLen; i++) {
                    name += (char) rawBytes[i + currPos];
                }

                currPos += currLen + 1;
                if (rawBytes[currPos] != 0)
                    name += ".";

                if (!isRecursion)
                    pointer += currLen+1;
            }
        }

        if (!isRecursion)
            pointer = currPos+1;
        return name;
    }

    /** Gets RecordType of the response.
     *
     * @return  RecordType associated with the response.
     */
    private RecordType getType(){
        RecordType t = RecordType.getByCode(byte2int(getSubArrayFromRaw(pointer, pointer+2)));
        pointer += 2;
        return t;
    }

    /** Gets TTL of the response.
     *
     * @return  Time to Live of response.
     */
    private int getTTL(){
        int TTL = byte2int(getSubArrayFromRaw(pointer, pointer+4));
        pointer += 4;
        return TTL;
    }

    /** Converts byte[] to integer.
     *
     * @param b     byte[] to convert.
     * @return      integer value of b.
     */
    private int byte2int(byte[] b){
        int value = 0;
        for (int i = 0; i <= b.length-1; i++)
            value = (value << 8) + (b[i] & 0xFF);
        return value;
    }

    /** Converts byte[] to binary string.
     *
     * @param bytes     byte[] to convert.
     * @return          converted string.
     */
    private String toBinary( byte[] bytes ) {
        StringBuilder sb = new StringBuilder(bytes.length * Byte.SIZE);
        for( int i = 0; i < Byte.SIZE * bytes.length; i++ )
            sb.append((bytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
        return sb.toString();
    }

    /** Add resource record to appropriate category.
     *
     * @param i     index of resource record in the response.
     * @param rr    resource record.
     */
    private void addToLists(int i, ResourceRecord rr) {
        if (i < anCount) {
            answers.add(rr);
        } else if (i >= anCount && i < nsCount+anCount){
            nameServers.add(rr);
        } else {
            addInfo.add(rr);
        }
    }

    /** Gets the hostname of one nameserver.
     *
     * @return      hostname.
     */
    public String getNSName(){
        if (nameServers.size() != 0)
            return nameServers.iterator().next().getHostName();
        else
            return null;
    }

    /** Checks for error in the response.
     *
     * @return  existence of error in response.
     */
    public boolean errorCheck(){
        char[] errorStr = toBinary(Error).toCharArray();
        //Check Z code
        if (errorStr[1] == '1' || errorStr[2] == '1' || errorStr[3] == '1') {
            return true;
        }

        //check RCODE for non zeros
        if (errorStr[4] == '1' || errorStr[5] == '1' || errorStr[6] == '1'|| errorStr[7] == '1') {
            return true;
        }
        return false;
    }
}
