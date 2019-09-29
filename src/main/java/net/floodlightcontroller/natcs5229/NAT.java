package net.floodlightcontroller.natcs5229;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IListener;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.loadbalancer.LBVip;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.util.FlowModUtils;
import org.kohsuke.args4j.CmdLineException;
import org.projectfloodlight.openflow.protocol.*;
import java.io.IOException;
import java.util.*;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Created by pravein on 28/9/17.
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();


    @Override
    public String getName() {
        return NAT.class.getName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }





    // Main Place to Handle PacketIN to perform NAT
    private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        IPacket pkt = eth.getPayload();

        if (eth.isBroadcast() || eth.isMulticast()) {
            if (pkt instanceof ARP) {
                ARP arpRequest = (ARP) eth.getPayload();
                IPv4Address targetProtocolAddress = arpRequest.getTargetProtocolAddress();
                if (RouterInterfaceMacMap.containsKey(targetProtocolAddress.toString())) {
                    MacAddress targetMacAddress = MacAddress.of(RouterInterfaceMacMap.get(targetProtocolAddress.toString()));
                    IPacket arpReply = new Ethernet()
                            .setSourceMACAddress(targetMacAddress)
                            .setDestinationMACAddress(eth.getSourceMACAddress())
                            .setEtherType(EthType.ARP)
                            .setVlanID(eth.getVlanID())
                            .setPriorityCode(eth.getPriorityCode())
                            .setPayload(new ARP()
                                    .setHardwareType(ARP.HW_TYPE_ETHERNET)
                                    .setProtocolType(ARP.PROTO_TYPE_IP)
                                    .setHardwareAddressLength((byte) 6)
                                    .setProtocolAddressLength((byte) 4)
                                    .setOpCode(ARP.OP_REPLY)
                                    .setSenderHardwareAddress(targetMacAddress)
                                    .setSenderProtocolAddress(arpRequest.getTargetProtocolAddress())
                                    .setTargetHardwareAddress(eth.getSourceMACAddress())
                                    .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress())
                            );
                    pushPacket(arpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY, (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)), cntx, true);
                    return Command.STOP;
                }
            }
        } else {
            if (pkt instanceof IPv4) {
                logger.info("send package");
                IPv4 ip_pkt = (IPv4) pkt;

                IPv4Address destIpAddress = ip_pkt.getDestinationAddress();
                String serverAddress = "10.0.0.11";
                String publicAddress = "10.0.0.1";
                if (serverAddress.equals(destIpAddress.toString())) {
                    logger.info("destination is server");
                    if (ip_pkt.getPayload() instanceof ICMP && ((ICMP) ip_pkt.getPayload()).getIcmpType() == 0x8) {
                        logger.info("and is icmp package request");
                        // 51 byte
//                        byte[] bytes = pi.getData();
//                        int identifier = (bytes[51] << 8) + bytes[52];
                        byte[] bytes = ((ICMP) ip_pkt.getPayload()).serialize();
                        int identifier = (bytes[5] << 8) + bytes[6];
                        logger.info("identifier {}", String.valueOf(identifier));
                        eth.setDestinationMACAddress(IPMacMap.get(serverAddress));
                        eth.setSourceMACAddress(RouterInterfaceMacMap.get(publicAddress));
                        ip_pkt.setSourceAddress(IPv4Address.of(publicAddress));
                        ip_pkt.resetChecksum();
                        pushPacket(eth, sw, OFBufferId.NO_BUFFER, (pi.getVersion().compareTo(OFVersion.OF_12) < 0) ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT), IPPortMap.get(serverAddress),
                                cntx, true);
                        return Command.STOP;
                    }
                } else if (publicAddress.equals(destIpAddress.toString())) {
                    logger.info("destination is public");
                    if (ip_pkt.getPayload() instanceof ICMP && ((ICMP) ip_pkt.getPayload()).getIcmpType() == 0x0) {
                        logger.info("and is icmp package reply");
                        eth.setDestinationMACAddress("00:00:00:00:00:02");
                        ip_pkt.setDestinationAddress(IPv4Address.of("192.168.0.20")); //todo
                        ip_pkt.resetChecksum();
                        pushPacket(eth, sw, OFBufferId.NO_BUFFER, (pi.getVersion().compareTo(OFVersion.OF_12) < 0) ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT), IPPortMap.get("192.168.0.20"),
                                cntx, true);
                        return Command.STOP;
                    }
                }
            }
        }
        return Command.CONTINUE;
    }

    /**
     * used to push any packet
     *
     * @param packet packet
     * @param sw sw
     * @param bufferId bufferId
     * @param inPort inPort
     * @param outPort outPort
     * @param cntx cntx
     * @param flush flush
     */
    public void pushPacket(IPacket packet,
                           IOFSwitch sw,
                           OFBufferId bufferId,
                           OFPort inPort,
                           OFPort outPort,
                           FloodlightContext cntx,
                           boolean flush) {
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(Integer.MAX_VALUE).build());
        pob.setActions(actions);
        pob.setBufferId(bufferId);
        pob.setInPort(inPort);
        if (pob.getBufferId() == OFBufferId.NO_BUFFER) {
            if (packet == null) {
                return;
            }
            byte[] packetData = packet.serialize();
            pob.setData(packetData);
        }
//        log.info(pob.build().toString());
        sw.write(pob.build());
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                return handlePacketIn(sw, (OFPacketIn)msg, cntx);
            default:
                break;
        }
        logger.warn("Received unexpected message {}", msg);
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(NAT.class);

        // Use the below HashMaps as per your need

        // Router Interface IP to Mac address Mappings
        RouterInterfaceMacMap.put("10.0.0.1","00:23:10:00:00:01");
        RouterInterfaceMacMap.put("192.168.0.1","00:23:10:00:00:02");
        RouterInterfaceMacMap.put("192.168.0.2","00:23:10:00:00:03");

        // IP to Router Interface mappings
        IPPortMap.put("192.168.0.10", OFPort.of(1));
        IPPortMap.put("192.168.0.20", OFPort.of(2));
        IPPortMap.put("10.0.0.11", OFPort.of(3));

        //Client/Server ip to Mac mappings
        IPMacMap.put("192.168.0.10", "00:00:00:00:00:01");
        IPMacMap.put("192.168.0.20", "00:00:00:00:00:02");
        IPMacMap.put("10.0.0.11", "00:00:00:00:00:03");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
