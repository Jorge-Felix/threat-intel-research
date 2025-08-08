import "elf"
import "hash"

rule Mirai_Botnet_File
{
    meta:
        description = "Detects Mirai botnet ELF binaries, including the 'Nomi' variant. This rule identifies samples based on known file hashes, unique strings related to process enumeration, persistence mechanisms, and hardcoded network indicators."
        author = "bigbudda"
        date = "2025-08-07"
        version = 2
        reference = "https://raw.githubusercontent.com/Jorge-Felix/threat-intel-research/refs/heads/main/Botnets/mirai-2024/report.md", "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/", "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759", "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"
        hash = "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba", "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
        tags = "CRIME, BOTNET, MIRAI, ELF, FILE"
        mitre_attack = "T1110.001, T1059, T1543.004, T1014, T1071.001, T1190, T1489"
        malware_family = "Mirai"
        malware_type = "Botnet"

    strings:
        // Core Mirai markers
        $miname = "Myname--is:" ascii
        $procnet = "/proc/net/tcp" ascii

        // Defense evasion via iptables
        $iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP" ascii
        $iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP" ascii

        // Persistence paths
        $path_persist1 = "/etc/rc.local" ascii
        $path_persist2 = "/var/run/gcc.pid" ascii

        // Watchdog and password-like strings
        $dir1 = "/dev/watchdog" ascii
        $dir2 = "/dev/misc/watchdog" ascii
        $pass1 = "PMMV" ascii
        $pass2 = "FGDCWNV" ascii
        $pass3 = "OMVJGP" ascii
        $pass4 = "ZOJFKRA" ascii

        // Hardcoded network indicators from C2 and dropper
        $ip_1 = "185.125.190.49" ascii
        $ip_2 = "91.189.91.49" ascii
        $ip_3 = "224.0.0.251" ascii
        $ip_4 = "24.12.1.98" ascii
        $ip_5 = "6.14.0.32" ascii
        $dropper_host = "154.91.254.95" ascii
        $dropper_path = "/rondo.i586" ascii
        $domain_arpa = "10.100.168.192.in-addr.arpa" ascii

    condition:
        // Must be an ELF file, typically small for IoT devices
        elf.is_elf and filesize < 500KB and
        (
            // High-confidence detection via known hash
            hash.sha256(0, filesize) in (
                "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba",
                "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd",
                "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
            )
            or
            // String-based detection requiring core markers and other indicators
            (
                all of ($miname, $procnet) and
                2 of (
                    1 of ($iptables*),
                    1 of ($path_persist*),
                    2 of ($ip_*),
                    $dropper_host,
                    (1 of ($dir*) and 1 of ($pass*))
                )
            )
        )
}
