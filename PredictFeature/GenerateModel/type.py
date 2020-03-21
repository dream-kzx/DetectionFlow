# coding=utf-8

class Attack():
    Type = {
        "normal": 0,
        "back": 1,  # dos
        "buffer_overflow": 2,  # u2r
        "ftp_write": 3,  # r2l
        "guess_passwd": 4,  # r2l
        "imap": 5,  # r2l
        "ipsweep": 6,  # probe
        "land": 7,  # dos
        "loadmodule": 8,  # u2r
        "multihop": 9,  # r2l
        "neptune": 10,  # dos
        "nmap": 11,  # probe
        "perl": 12,  # u2r
        "phf": 13,  # r2l
        "pod": 14,  # dos
        "portsweep": 15,  # probe
        "rootkit": 16,  # u2r
        "satan": 17,  # probe
        "smurf": 18,  # dos
        "spy": 19,  # r2l
        "teardrop": 20,  # dos
        "warezclient": 21,  # r2l
        "warezmaster": 22,  # r2l
        "saint": 23,
        "mscan": 24,
        "apache2": 25,
        "snmpgetattack": 26,
        "processtable": 27,
        "httptunnel": 28,
        "ps": 29,
        "snmpguess": 30,
        "mailbomb": 31,
        "named": 32,
        "sendmail": 33,
        "xterm": 34,
        "worm": 35,
        "xlock": 36,
        "xsnoop": 37,
        "sqlattack":38,
        "udpstorm":39,
    }


class Service():
    Type = {
        "other": 0, "private": 1, "ecr_i": 2, "urp_i": 3, "urh_i": 4,
        "red_i": 5, "eco_i": 6, "tim_i": 7, "oth_i": 8, "domain_u": 9,
        "tftp_u": 10, "ntp_u": 11, "IRC": 12, "X11": 13, "Z39_50": 14,
        "aol": 15, "auth": 16, "bgp": 17, "courier": 18, "csnet_ns": 19,
        "ctf": 20, "daytime": 21, "discard": 22, "domain": 23, "echo": 24,
        "efs": 25, "exec": 26, "finger": 27, "ftp": 28, "ftp_data": 29,
        "gopher": 30, "harvest": 31, "hostnames": 32, "http": 33, "http_2784": 34,
        "http_443": 35, "http_8001": 36, "icmpd": 37, "imap4": 38, "iso_tsap": 39,
        "klogin": 40, "kshell": 41, "ldap": 42, "link": 43, "login": 44,
        "mtp": 45, "name": 46, "netbios_dgm": 47, "netbios_ns": 48, "netbios_ssn": 49,
        "netstat": 50, "nnsp": 51, "nntp": 52, "pm_dump": 53, "pop_2": 54,
        "pop_3": 55, "printer": 56, "remote_job": 57, "rje": 58, "shell": 59,
        "smtp": 60, "sql_net": 61, "ssh": 62, "sunrpc": 63, "supdup": 64,
        "systat": 65, "telnet": 66, "time": 67, "uucp": 68, "uucp_path": 69,
        "vmnet": 70, "whois": 71}


class Flag():
    Type = {
        "SF": 1,
        "S0": 2,
        "S1": 3,
        "S2": 4,
        "S3": 5,
        "REJ": 6,
        "RSTOS0": 7,
        "RSTO": 8,
        "RSTR": 9,
        "SH": 10,
        "OTH": 13}


class Protocol():
    Type = {
        "icmp": 1,
        "tcp": 6,
        "udp": 17
    }
