import "hash"
import "pe"

rule Mirai_Botnet_Detection : MALW Mirai
{
    meta:
        description = "Mirai Botnet Detection - Based on hashes, strings, and behavioral indicators"
        author = "Jorge Felix Gonzalez Arias"
        date = "2025-07-14"
        version = "1.1"
        credits = "Based on the original work of Felipe Molina / @felmoltor and Joan Soriano / @joanbtl"
        ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
        ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
        ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"
        SHA256_1 = "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba"
        SHA256_2 = "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd"
        SHA256_3 = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"

    strings:
        // Mirai-specific markers
        $miname        = "Myname--is:"
        $iptables1     = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
        $iptables2     = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
        $procnet       = "/proc/net/tcp"

        // Files and embedded password-like strings
        $dir1          = "/dev/watchdog"
        $dir2          = "/dev/misc/watchdog"
        $pass1         = "PMMV"
        $pass2         = "FGDCWNV"
        $pass3         = "OMVJGP"
        $pass4         = "ZOJFKRA"

        // Hardcoded network indicators
        $ip_1          = "185.125.190.49"
        $ip_2          = "91.189.91.49"
        $ip_3          = "224.0.0.251"
        $ip_4          = "24.12.1.98"
        $ip_5          = "6.14.0.32"
        $domain_arpa   = "10.100.168.192.in-addr.arpa"

        // Commonly used ports
        $port_22       = ":22"
        $port_80       = ":80"
        $port_123      = ":123"
        $port_161      = ":161"
        $port_443      = ":443"
        $port_873      = ":873"
        $port_9103     = ":9103"

    condition:
        // Exact detection by SHA256 hash
        hash.sha256(0, filesize) in (
            "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba",
            "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd",
            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
        )
        or
        // Behavior and contextual detection
        (
            all of ($miname, $iptables1, $iptables2, $procnet) and
            (
                any of ($dir1, $dir2) and any of ($pass1, $pass2, $pass3, $pass4)
                or any of ($ip_*)
                or $domain_arpa
                or 2 of ($port_*)
            )
        )
}
