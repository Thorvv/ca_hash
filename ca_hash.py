# coding=utf-8
import sys

ip_to_num = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])


def normal_hash_32(five_dict):

    if five_dict['dip'] == '0':
        get_hash = ip_to_num(five_dict['sip']) & 0x1fff
        dmac = (get_hash + 1) % 7
        return dmac

    if five_dict['sip'] == '0':
        get_hash = ip_to_num(five_dict['dip']) & 0x1fff
        dmac = (get_hash + 1) % 7
        return dmac

    if five_dict['dip'] != '0' and five_dict['sip'] != '0':
        get_hash = (ip_to_num(five_dict['dip']) + ip_to_num(five_dict['sip'])) & 0x1fff
        dmac = (get_hash + 1) % 7
        return dmac

    else:
        return None


def nisac_hash_32(five_dict):

    if five_dict['dip'] == '0':
        ht = ip_to_num(five_dict['sip']) ^ 0
        ht_116 = ((ht & 0xFFFF0000) >> 16)
        ht_h16 = ht & 0xFFFF
        ht16 = ht_116 ^ ht_h16
        ht16_h4 = ht16 & 0xF000
        ht16_m4 = ht16 & 0x0F00
        ht16_h4 >>= 12
        ht16_m4 >>= 8
        ht4 = ht16_h4 ^ ht16_m4
        ht_18 = ht16 & 0xFF
        ht12 = ht_18 | (ht4 << 8)
        return ht12 >> 2

    if five_dict['sip'] == '0':
        ht = ip_to_num(five_dict['dip']) ^ 0
        ht_116 = (ht & 0xFFFF0000) >> 16
        ht_h16 = ht & 0xFFFF
        ht16 = ht_116 ^ ht_h16
        ht16_h4 = ht16 & 0xF000
        ht16_m4 = ht16 & 0x0F00
        ht16_h4 >>= 12
        ht16_m4 >>= 8
        ht4 = ht16_h4 ^ ht16_m4
        ht_18 = ht16 & 0xFF
        ht12 = ht_18 | (ht4 << 8)
        return ht12 >> 2

    if five_dict['sip'] != '0' and five_dict['dip'] != '0':
        ht = ip_to_num(five_dict['dip']) ^ ip_to_num(five_dict['sip'])
        ht_116 = (ht & 0xFFFF0000) >> 16
        ht_h16 = ht & 0xFFFF
        ht16 = ht_116 ^ ht_h16
        ht16_h4 = ht16 & 0xF000
        ht16_m4 = ht16 & 0x0F00
        ht16_h4 >>= 12
        ht16_m4 >>= 8
        ht4 = ht16_h4 ^ ht16_m4
        ht_18 = ht16 & 0xFF
        ht12 = ht_18 | (ht4 << 8)
        return ht12 >> 2

    else:
        return None


def crc_hash(five_dict, sip_mask=0, dip_mask=0, sport_mask=0, dport_mask=0, proto_mask=0):
    # define those 5 mask yourself
    sip_bin = bin(ip_to_num(five_dict['sip']))[2:]
    dip_bin = bin(ip_to_num(five_dict['dip']))[2:]
    if len(sip_bin) == 32:
        new_sip = sip_bin.zfill(128)
    else:
        new_sip = sip_bin

    if len(dip_bin) == 32:
        new_dip = dip_bin.zfill(128)
    else:
        new_dip = dip_bin

    h1_sip = hash1(new_sip)
    h1_dip = hash1(new_dip)

    m_sip = 0 if (sip_mask == 1) else h1_sip
    m_dip = 0 if (dip_mask == 1) else h1_dip
    m_sport = 0 if (sport_mask == 1) else five_dict['sport']
    m_dport = 0 if (dport_mask == 1) else five_dict['dport']
    m_proto = 0 if (proto_mask == 1) else five_dict['proto']

    first_ip = m_sip if (m_sip > m_dip) else m_dip
    second_ip = m_dip if (m_sip > m_dip) else m_sip
    first_port = m_sport if (m_sport > m_dport) else m_dport
    secont_port = m_dport if (m_sport > m_dport) else m_sport

    m_proto = bin(int(m_proto))[2:].zfill(8)
    first_port = bin(int(first_port))[2:].zfill(16)
    secont_port = bin(int(secont_port))[2:].zfill(16)
    key_flag = first_ip + second_ip + m_proto + first_port + secont_port
    key = key_flag.zfill(128)
    result = hash2(str(key))
    dmac_flag = int(result) & 0x1fff
    dmac = dmac_flag % int(five_dict['port_num'])
    ph_out = (dmac_flag + 1) % int(five_dict['port_num'])
    return dmac, ph_out


def out_hash_33(five_dict):
    if five_dict['dip'] == '0':
        sip = ip_to_num(five_dict['sip'])
        dmac_s = (sip % int(five_dict['port_num'])) + 1
        return dmac_s
    if five_dict['sip'] == '0':
        dip = ip_to_num(five_dict['dip'])
        dmac_d = (dip % int(five_dict['port_num'])) + 1
        return dmac_d
    else:
        return None


def hash1(new_ip):
    crc_ieee = 0x04C11DB7
    crc = 0xffffffff
    for ptr in new_ip:
        ptr = int(ptr)
        i = 0x80
        while i != 0:
            if (crc & 0x80000000) != 0:
                crc <<= 1
                crc &= 0xffffffff
                crc ^= crc_ieee
            else:
                crc <<= 1
                crc &= 0xffffffff
            if (ptr & i) != 0:
                crc &= 0xffffffff
                crc ^= crc_ieee
            i /= 2
    return bin(crc)[2:]


def hash2(key):
    crc_ccitt = 0x1021
    crc = 0xffff
    for ptr in key:
        ptr = int(ptr)
        i = 0x80
        while i != 0:
            crc *= 2
            if (crc & 0x10000) != 0:
                crc ^= 0x11021
            if (ptr & i) != 0:
                crc ^= crc_ccitt
            i /= 2
    return bin(crc)[2:]


def main(argv):
    five_dict = {'dip': argv[1], 'sip': argv[2], 'dport': argv[3],
                 'sport': argv[4], 'proto': argv[5], 'port_num': argv[6]}

    # dmac = normal_hash_32(five_dict)
    # print dmac
    # hash = nisac_hash_32(five_dict)
    # print hash
    # dmac = out_hash_33(five_dict)
    # print hash
    dmac, ph_out = crc_hash(five_dict)
    print dmac
    print ph_out

if __name__ == '__main__':
    main(sys.argv)

