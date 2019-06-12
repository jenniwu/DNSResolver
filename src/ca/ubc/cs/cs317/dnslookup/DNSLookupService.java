package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static final int QUERY_ID_BOUND = 65536;
    private static final int MAX_QUERY = 65536;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();
    private static int randInt = 0;
    private static boolean authFlag;
    private static boolean repeatQuery;
    private static int numberSentQuery;
    private static List<QueryLog> queryLogs;
    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                // create a new DNS node with the hostname and type, then getResult
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        //cache.flushCache();
        queryLogs = new LinkedList<>();
        repeatQuery = false;
        authFlag=false;
        numberSentQuery=0;
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        //First check if it's a CNAME of something already in the cache
        Set<ResourceRecord> existingCNAME = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
        if(existingCNAME.size()!=0) {
            retrieveResultsFromServer(new DNSNode(existingCNAME.iterator().next().getTextResult(),node.getType()), rootServer);
        }else{
            retrieveResultsFromServer(node, rootServer);
        }

        //After retrieving for the first round, check whether what we get is a CNAME
        Set<ResourceRecord> currResultAddress = cache.getCachedResults(node);
        Set<ResourceRecord> currResultCNAME = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));

        if (currResultAddress.size() == 0 && currResultCNAME.size() != 0) {
            String host_CNAME = currResultCNAME.iterator().next().getTextResult();
            //Linked-List-Like-CNAMEs detector
            int CNAMEcounter=0;//Try at most MAX_QUERY times
            while (cache.getCachedResults(new DNSNode(host_CNAME, RecordType.CNAME)).size() != 0&&CNAMEcounter<=MAX_QUERY) {
                host_CNAME = cache.getCachedResults(new DNSNode(host_CNAME, RecordType.CNAME)).iterator().next().getTextResult();
                CNAMEcounter++;
            }

            Set<ResourceRecord> currCNAMEAddress = cache.getCachedResults(new DNSNode(host_CNAME, node.getType()));
            DNSNode newNode = new DNSNode(host_CNAME, node.getType());
            if (currCNAMEAddress.size() == 0)
                return getResults(newNode,indirectionLevel+1);
            else
                return currCNAMEAddress;
        }

        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // checks if node is already in the cache; if it is, just skip this query
        Set<ResourceRecord> currCache = cache.getCachedResults(node);
        if(!currCache.isEmpty()){return;}

        //check how many queries are sent
        if(numberSentQuery>MAX_QUERY)
            return;

        //generate query
        DNSQuery query = new DNSQuery(node);
        if (!repeatQuery)
            randInt = random.nextInt(QUERY_ID_BOUND);
        query.setQueryID(randInt);

        byte[] nodeInBytes = query.getQueryInBytes();   // gets DNSQuery in bytes
        byte[] qID = Arrays.copyOfRange(nodeInBytes, 0,2);  // gets queryID in bytes
        byte[] buf = new byte[1024];

        // create datagram packets for sending and receiving query
        DatagramPacket packetOut = new DatagramPacket(nodeInBytes, nodeInBytes.length, server, DEFAULT_DNS_PORT);
        DatagramPacket packetIn = new DatagramPacket(buf, buf.length);

        try {
            socket.send(packetOut);
            DNSResponse dnsResp;

            //keep polling on receive until we get a consistant response
            do {
                socket.receive(packetIn);
                dnsResp=new DNSResponse(packetIn.getData());
            }while(!Arrays.equals(qID, dnsResp.qID));

            //Set flag to off since we have consistant response
            repeatQuery = false;
            dnsResp.cacheResourceRecords();

            // check for error in the response
            if (dnsResp.errorCheck())
                throw new ResponseErrorException("Error in Response.");

            //Real time printing of query
            QueryLog queryLog=new QueryLog(query, server, dnsResp);
            if(verboseTracing) {
                queryLog.printThisLog();
            }

            //Only perform next lookup if we don't an authorative response
            if (!dnsResp.isAuth) {
                //Just return if the server tells an answer
                if(dnsResp.answers.size()!=0)
                    return;
                //get a list of dnservers who have an actual ip address in our cache
                Set<DNSNode> authoratitiveNSWithIPv4=new HashSet<>();
                for (DNSNode dnsNode : dnsResp.authoratitiveNS) {
                    //Retrieve ip address for a nameserver
                    Set<ResourceRecord> dnsIPCache = cache.getCachedResults(new DNSNode(dnsNode.getHostName(), RecordType.A));
                    if (dnsIPCache.size() != 0){
                        authoratitiveNSWithIPv4.add(dnsNode);
                    }
                }

                //If current NS have no associated IP addresses, then search for one nameserver
                int max=dnsResp.authoratitiveNS.size();
                while (authoratitiveNSWithIPv4.size() == 0){
                    if(max<0)
                        throw new ResponseErrorException("No available nameserver");//We cannot find ipv4 for any nameservers, terminate program

                    DNSNode dnsLookup=new DNSNode(dnsResp.authoratitiveNS.iterator().next().getHostName(), RecordType.A);
                    getResults(dnsLookup,0);//
                    if(cache.getCachedResults(new DNSNode(dnsLookup.getHostName(), RecordType.A)).size()>0)
                        authoratitiveNSWithIPv4.add(dnsLookup);
                    max--;
                }

                // iterate all the nameservers with an ip address, keep trying on all nameservers until our query is resolved
                for (DNSNode dnsNode : authoratitiveNSWithIPv4) {
                    InetAddress newServer;

                    //get ipv4 addresses for this nameserver
                    Set<ResourceRecord> nsCache = cache.getCachedResults(new DNSNode(dnsNode.getHostName(), RecordType.A));
                    for (ResourceRecord nsRec : nsCache) {
                        if (nsRec.getType() == RecordType.A) {
                            newServer = nsRec.getInetResult();
                            retrieveResultsFromServer(node, newServer);
                            break;
                        }
                    }

                    // stop trying other name servers if address resolves
                    // determine A,AAAA,CNAME,SOA,MX,OTHER as resolved
                    if (!cache.getCachedResults(node).isEmpty() ||
                            !cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME)).isEmpty()||
                            !cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.MX)).isEmpty()||
                            !cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.SOA)).isEmpty()||
                            !cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.OTHER)).isEmpty()||
                            repeatQuery||authFlag) {
                        return;
                    }
                }
            }else{
                authFlag=true;
            }
        } catch (SocketTimeoutException e) {     //socket timeout exception or error, resend query
            //print the timeout query
            if (verboseTracing) {
                System.out.println("\n");
                System.out.println("Query ID     " + randInt + " " +
                        node.getHostName() + " " + node.getType() + " --> " + server.getHostAddress());
            }
            //Query is sent at most two times, give up if more
            if (!repeatQuery) {
                repeatQuery = true;
                retrieveResultsFromServer(node, server);
            }else{//If this is the second timeout then we give up
                return;
            }
        }catch (ResponseErrorException e){
            //Just give up the current lookup
        }catch (Exception e) { // print some unknown error
            //System.out.println("Error: "+e);//Debugging message
            throw new Error(e);
        }
    }

    //Unused provided function
    /*
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
    */

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }


    //////////////HELPER FUNCTIONS BELOW/////////////////////

    private static List<String> getSearchedNames(){
        List<String> names = new ArrayList<>();
        for (QueryLog ql : queryLogs) {
            names.add((ql.dnsResp.getNSName()));
        }

        return names;
    }

    private static boolean isInList(String host, List<String> hosts){
        return  hosts.contains(host);
    }
}
