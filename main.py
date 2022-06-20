from time import sleep
from pathlib import Path
from scapy.all import conf, Emph, ConditionalField, Packet, SetGen
from scapy.layers.inet import UDP, TCP
from scapy.utils import rdpcap

CURRENT_PATH = Path(__file__).parent
RESULT_FILE = CURRENT_PATH / 'results.txt'

fragmented_pkt = 0

valid_layer = ["TCP", "UDP", "ICMP", "IP"]
valid_param = [
    "chksum", "version", "len", "flags", "frag", "ttl", "src", "dst", "sport", "dport", "ack", "seq", "proto"
]


def show_or_dump_summary(pkt, dump=False, indent=3, lvl="", label_lvl="", first_call=True):
    global fragmented_pkt
    ct = conf.color_theme
    s = ""

    if pkt.name in valid_layer:

        s = f'{label_lvl}{ct.punct("!! ")} {ct.layer_name(pkt.name)} {ct.punct(" !!")} \n'
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
                s += f"{label_lvl + lvl}  \\{ncol(f.name)}{pad}\\\n"
                fvalue_gen = SetGen(
                    fvalue,
                    _iterpacket=0
                )  # type: SetGen[Packet]
                for fvalue in fvalue_gen:
                    s += show_or_dump_summary(
                        fvalue, dump=dump, indent=indent, label_lvl=label_lvl + lvl + "   |", first_call=False
                    )
            else:
                pad = max(0, 10 - len(f.name)) * " "
                begn = f'{label_lvl + lvl}  {ncol(f.name)}{pad}{ct.punct("->")} '
                reprval = f.i2repr(pkt, fvalue)
                if isinstance(reprval, str):
                    reprval = reprval.replace("\n", "\n" + " " * (len(label_lvl) + len(lvl) + len(f.name) + 4))

                if "chksum" in f.name:
                    reprval = bin(int(reprval, 16))[2:]

                if 'IP' in pkt.name and 'flags' in f.name and 'MF' in reprval:
                    fragmented_pkt += 1

                s += f"{begn}{vcol(reprval)}\n"
    if pkt.payload:
        s += show_or_dump_summary(
            pkt.payload,
            dump=dump,
            indent=indent,
            lvl=lvl + (" " * indent * pkt.show_indent),
            label_lvl=label_lvl,
            first_call=False
        )

    if first_call:
        if dump:
            print(f'{s} \n', file=RESULT_FILE.open('a'))
        else:
            print(s)
            print('\n', '─' * 80, '\n')

        return None
    else:
        return s


def scapy_summary(packet_list):
    print(f"Total packets -> {len(packet_list)}")
    print(f"Total TCP packets -> {len(packet_list[TCP])} : {round(100 * len(packet_list[TCP]) / len(packet_list))}%")
    print(f"Total UDP packets -> {len(packet_list[UDP])} : {round(100 * len(packet_list[UDP]) / len(packet_list))}%")

    sleep(3)
    for r in packet_list.res:
        show_or_dump_summary(r, True)

    print(f"Total fragmented packets -> {fragmented_pkt}")


if __name__ == '__main__':
    if RESULT_FILE.exists():
        RESULT_FILE.unlink()
    packets = rdpcap(str(CURRENT_PATH / 'target.pcap'))
    scapy_summary(packets)
