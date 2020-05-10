# coding=utf-8

class Attack():
    Type = {
        "normal": 0,
        "loadmodule": 1,  # U2R
        "buffer_overflow": 2,  # U2R
        "perl": 3,  # U2R
        "rootkit": 4,  # U2R
        "ps": 5,  # U2R
        "httptunnel": 6,  # U2R
        "xterm": 7,  # U2R
        "sqlattack": 8,  # U2R

        "snmpgetattack": 9,  # R2L
        "phf": 10,  # R2L
        "warezmaster": 11,  # R2L
        "warezclient": 12,  # R2L
        "multihop": 13,  # R2L
        "guess_passwd": 14,  # R2L
        "spy": 15,  # R2L
        "imap": 16,  # R2L
        "ftp_write": 17,  # R2L
        "sendmail": 18,  #
        "xlock": 19,  # R2L
        "worm": 20,  # R2L
        "xsnoop": 21,  # R2L
        "named": 22,  # R2L
        "snmpguess": 23,  # R2L

        "nmap": 24,  # Probe
        "portsweep": 25,  # Probe
        "mscan": 26,  # Probe
        "satan": 27,  # Probe
        "ipsweep": 28,  # Probe
        "saint": 29,  # Probe

        "apache2": 30,  # DOS
        "back": 31,  # DOS
        "smurf": 32,  # DOS
        "pod": 33,  # DOS
        "land": 34,  # DOS
        "teardrop": 35,  # DOS
        "neptune": 36,  # DOS
        "udpstorm": 37,  # DOS
        "processtable": 38,  # DOS
        "mailbomb": 39,  # DOS

    }

    R2L = [
        "snmpgetattack",  # R2L
        "phf",  # R2L
        "warezmaster",  # R2L
        "warezclient",  # R2L
        "multihop",  # R2L
        "guess_passwd",  # R2L
        "spy",  # R2L
        "imap",  # R2L
        "ftp_write",  # R2L
        "sendmail",  #
        "xlock",  # R2L
        "worm",  # R2L
        "xsnoop",  # R2L
        "named",  # R2L
        "snmpguess"]

    U2R = ["loadmodule",  # U2R
           "buffer_overflow",  # U2R
           "perl",  # U2R
           "rootkit",  # U2R
           "ps",  # U2R
           "httptunnel",  # U2R
           "xterm",  # U2R
           "sqlattack"]

    DOS = ["apache2",  # DOS
           "back",  # DOS
           "smurf",  # DOS
           "pod",  # DOS
           "land",  # DOS
           "teardrop",  # DOS
           "neptune",  # DOS
           "udpstorm",  # DOS
           "processtable",  # DOS
           "mailbomb"]

    PROBE = ["nmap",  # Probe
             "portsweep",  # Probe
             "mscan",  # Probe
             "satan",  # Probe
             "ipsweep",  # Probe
             "saint"]


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
        "icmp": 0,
        "tcp": 1,
        "udp": 2
    }
