import sys

from ptf.testutils import *

try:
    from scapy.all import *
except ImportError:
    sys.exit("XNT Need to install scapy for packet parsing")

class VXLAN_GPE_INT(Packet):
    name = "VXLAN_GPE_INT_header"
    fields_desc = [ XByteField("int_type", 0x01),
                    XByteField("rsvd", 0x00),
                    XByteField("length", 0x00),
                    XByteField("next_proto", 0x03) ]

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 2), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField("rsvd1", 0, 5), BitField("ins_cnt", 1, 5),
                    BitField("max_hop_cnt", 32, 8),
                    BitField("total_hop_cnt", 0, 8),
                    ShortField("inst_mask", 0x8000),
                    ShortField("rsvd2", 0x0000)]

class INT_hop_info(Packet):
    name = "INT_hop_info"
    fields_desc = [ BitField("bos", 0, 1),
                    XBitField("val", 0x7FFFFFFF, 31) ]

class VXLAN_GPE(Packet):
    name = "VXLAN_GPE"
    fields_desc = [ FlagsField("flags", 0x18, 8, ['R', 'R', 'R', 'I', 'P', 'R', 'R', 'R']),
                    XShortField("reserved1", 0x0000),
                    XByteField("next_proto", 0x03),
                    ThreeBytesField("vni", 0),
                    XByteField("reserved2", 0x00)]


def vxlan_gpe_int_src_packet(eth_dst='00:77:66:55:44:33',
                             eth_src='00:22:22:22:22:22',
                             ip_id=0x0,
                             ip_dst='10.10.10.1',
                             ip_src='192.168.0.1',
                             ip_ttl=64,
                             udp_sport=101,
                             with_udp_chksum=False,
                             vxlan_vni=0x1234,
                             int_inst_mask=0xAC00,
                             int_inst_cnt=4,
                             max_hop_cnt=32,
                             inner_frame=None):

    udp_pkt = simple_udp_packet(
        pktlen=0,
        eth_dst=eth_dst,
        eth_src=eth_src,
        ip_dst=ip_dst,
        ip_src=ip_src,
        ip_ttl=ip_ttl,
        udp_sport=udp_sport,
        udp_dport=4790,
        with_udp_chksum=with_udp_chksum,
    )

    vxlan_pkt = udp_pkt / VXLAN_GPE(vni = vxlan_vni)

    vxlan_pkt['VXLAN_GPE'].next_proto = 0x5
    int_header = VXLAN_GPE_INT()
    int_header.length = 3 # this header(4) + INT meta header (8)
    int_meta_header = INT_META_HDR(ins_cnt=int_inst_cnt,
                                   max_hop_cnt=max_hop_cnt, inst_mask=int_inst_mask)
    return vxlan_pkt / int_header / int_meta_header / inner_frame

def vxlan_gpe_int_packet_add_hop_info(Packet,
                                      bos=False,
                                      val=0x7FFFFFFF, incr_cnt=0):
    # Find the start of INT data (following INT_META_HDR)
    meta_hdr = Packet[INT_META_HDR]
    if meta_hdr == None:
        return Packet

    # copy the packet and truncate everything after META_HDR
    new_pkt = Packet.copy()
    new_pkt[INT_META_HDR].remove_payload()
    new_pkt = new_pkt/INT_hop_info(bos=bos, val=val)/Packet[INT_META_HDR].payload
    # update all the headers - IP UDP header lens are updated automatically
    new_pkt[INT_META_HDR].total_hop_cnt += incr_cnt
    new_pkt[VXLAN_GPE_INT].length += 1

    return new_pkt
