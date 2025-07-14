import "hash"
import "elf"

rule Mirai_JFGA_Generic : MALW
{
    meta:
        description = "Mirai Botnet Variant - Generic Architecture Detection"
        author = "Jorge Felix Gonzalez Arias"
        date = "2025-07-14"
        version = "1.1"
        ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
        ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
        ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

    strings:
        $miname = "Myname--is:"
        $iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
        $iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
        $procnet = "/proc/net/tcp"
        $jfga_sig = "JFGA_Mirai_2025" // Unique identifier
        $c2_ip = "185.125.190.49" // From your provided data
        $dns_arpa = "in-addr.arpa" // Related to 10.100.168.192.in-addr.arpa

    condition:
        elf.type == elf.ET_EXEC and
        ($miname or $jfga_sig) and ($iptables1 or $iptables2) and $procnet and
        ($c2_ip or $dns_arpa)
}

rule Mirai_JFGA_MIPS_LSB : MALW
{
    meta:
        description = "Mirai Botnet Variant - MIPS LSB Detection"
        author = "Jorge Felix Gonzalez Arias"
        date = "2025-07-14"
        version = "1.1"
        ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
        ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
        ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

    strings:
        $miname = "Myname--is:"
        $iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
        $iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
        $procnet = "/proc/net/tcp"
        $jfga_sig = "JFGA_Mirai_MIPS" // Unique for MIPS
        $c2_ip = "185.125.190.49"
        $multicast = "224.0.0.251" // From your provided data

    condition:
        elf.type == elf.ET_EXEC and
        elf.machine == elf.EM_MIPS and
        ($miname or $jfga_sig) and ($iptables1 or $iptables2) and $procnet and
        ($c2_ip or $multicast)
}

rule Mirai_JFGA_ARM_LSB : MALW
{
    meta:
        description = "Mirai Botnet Variant - ARM LSB Detection"
        author = "Jorge Felix Gonzalez Arias"
        date = "2025-07-14"
        version = "1.1"
        ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
        ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
        ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

    strings:
        $miname = "Myname--is:"
        $iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
        $iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
        $procnet = "/proc/net/tcp"
        $jfga_sig = "JFGA_Mirai_ARM" // Unique for ARM
        $c2_ip = "185.125.190.49"
        $dns_arpa = "in-addr.arpa"

    condition:
        elf.type == elf.ET_EXEC and
        elf.machine == elf.EM_ARM and
        ($miname or $jfga_sig) and ($iptables1 or $iptables2) and $procnet and
        ($c2_ip or $dns_arpa)
}

rule Mirai_JFGA_Downloader : MALW
{
    meta:
        description = "Mirai Botnet Downloader Variant"
        author = "Jorge Felix Gonzalez Arias"
        date = "2025-07-14"
        version = "1.1"
        ref1 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

    strings:
        $dwnl1 = "GET /mirai/" // Downloader pattern
        $dwnl2 = "dvrHelper"
        $jfga_sig = "JFGA_Mirai_Dwnl" // Unique for downloader
        $c2_ip = "185.125.190.49"
        $wget = "wget http" // Common in Mirai downloaders

    condition:
        elf.type == elf.ET_EXEC and
        ($dwnl1 or $dwnl2 or $jfga_sig) and ($c2_ip or $wget)
}

rule Mirai_JFGA_Variant_2025 : MALW
{
    meta:
        description = "Mirai Botnet Variant 2025 with Network Activity"
        author = "Jorge Felix Gonzalez Arias"
        date = "2025-07-14"
        version = "1.1"
        hash = "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba"

    strings:
        $watchdog = "/dev/watchdog" // Persistence mechanism
        $c2_ip = "185.125.190.49"
        $multicast = "224.0.0.251"
        $dns_arpa = "in-addr.arpa"
        $jfga_sig = "JFGA_Mirai_2025_Variant"
        $telnet = "telnetd" // Common in Mirai for propagation

    condition:
        elf.type == elf.ET_EXEC and
        ($watchdog or $telnet) and ($c2_ip or $multicast or $dns_arpa) and $jfga_sig
}
