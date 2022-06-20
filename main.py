from scapy.all import *
from scapy.layers.inet import UDP, TCP
from scapy.utils import rdpcap

fragmented_pkt = 0

valid_layer = ["TCP", "UDP", "ICMP", "IP"]
valid_param = [
    "chksum", "version", "len", "flags", "frag", "ttl", "src", "dst", "sport", "dport", "ack", "seq", "proto"
]


def show_or_dump_summary(pkt, dump=False,
                         indent=3,
                         lvl="",
                         label_lvl="",
                         first_call=True
                         ):
    global fragmented_pkt
    if dump:
        from scapy.themes import AnsiColorTheme
        ct = AnsiColorTheme()  # No color for dump output
    else:
        ct = conf.color_theme
    s = ""

    if ct.layer_name(pkt.name) in valid_layer:

        s = "%s%s %s %s \n" % (label_lvl,
                               ct.punct("!! "),
                               ct.layer_name(pkt.name),
                               ct.punct(" !!"))
        for f in pkt.fields_desc:
            if f.name not in valid_param:
                continue
            if isinstance(f, ConditionalField) and not f._evalcond(pkt):
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
            fvalue = pkt.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and isinstance(fvalue, list)):  # noqa: E501
                pad = max(0, 10 - len(f.name)) * " "
                s += "%s  \\%s%s\\\n" % (label_lvl + lvl, ncol(f.name), pad)
                fvalue_gen = SetGen(
                    fvalue,
                    _iterpacket=0
                )  # type: SetGen[Packet]
                for fvalue in fvalue_gen:
                    s += show_or_dump_summary(fvalue, dump=dump, indent=indent, label_lvl=label_lvl + lvl + "   |",
                                              first_call=False)  # noqa: E501
            else:
                pad = max(0, 10 - len(f.name)) * " "
                begn = "%s  %s%s%s " % (label_lvl + lvl,
                                        ncol(f.name),
                                        pad,
                                        ct.punct("->"),)
                reprval = f.i2repr(pkt, fvalue)
                if isinstance(reprval, str):
                    reprval = reprval.replace("\n", "\n" + " " * (len(label_lvl) +  # noqa: E501
                                                                  len(lvl) +
                                                                  len(f.name) +
                                                                  4))

                if "chksum" in f.name:
                    reprval = bin(int(reprval, 16))[2:]

                if 'IP' in ct.layer_name(pkt.name) and 'flags' in f.name and 'MF' in reprval:
                    fragmented_pkt += 1

                s += "%s%s\n" % (begn, vcol(reprval))
    if pkt.payload:
        s += show_or_dump_summary(pkt.payload,  # type: ignore
                                  dump=dump,
                                  indent=indent,
                                  lvl=lvl + (" " * indent * pkt.show_indent),
                                  label_lvl=label_lvl,
                                  first_call=False
                                  )

    if first_call and not dump:
        print(s)

        return None
    else:
        return s


def scapy_summary(packet_list):
    global fragmented_pkt
    print(f"Total packets -> {len(packet_list)}")
    print(f"Total TCP packets -> {len(packet_list[TCP])} : {round(100 * len(packet_list[TCP]) / len(packet_list))}%")
    print(f"Total UDP packets -> {len(packet_list[UDP])} : {round(100 * len(packet_list[UDP]) / len(packet_list))}%")

    time.sleep(5)
    for r in packet_list.res:
        show_or_dump_summary(r)
        print('\n', '─' * 80, '\n')

    print(f"Total fragmented packets -> {fragmented_pkt}")


if __name__ == '__main__':
    packets = rdpcap('C:\\Users\\patro\\Desktop\\Sina.pcap')
    scapy_summary(packets)
