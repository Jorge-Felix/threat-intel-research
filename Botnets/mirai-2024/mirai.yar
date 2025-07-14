import "hash"
import "pe"

rule Mirai_Botnet_Detection : MALW
{
	meta:
		description = "Mirai Botnet Detection - Detecta muestras especÃ­ficas de la botnet Mirai"
		author = "Jorge Felix Gonzalez Arias"
		date = "2025-07-14"
		version = "1.0"
		credits = "Basado en trabajo original de Felipe Molina / @felmoltor y Joan Soriano / @joanbtl"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"
		
		// Hashes SHA256 especÃ­ficos de la botnet
		SHA256_1 = "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba"
		SHA256_2 = "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd"
		SHA256_3 = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
		
		// InformaciÃ³n de red asociada
		ip_1 = "185.125.190.49"
		ip_2 = "91.189.91.49"
		ip_3 = "224.0.0.251"
		domain = "10.100.168.192.in-addr.arpa"

	strings:
		// Cadenas caracterÃ­sticas de Mirai
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"
		
		// Cadenas adicionales de variantes
		$dir1 = "/dev/watchdog"
		$dir2 = "/dev/misc/watchdog"
		$pass1 = "PMMV"
		$pass2 = "FGDCWNV"
		$pass3 = "OMVJGP"
		$pass4 = "ZOJFKRA"
		
		// Cadenas de red y comunicaciÃ³n
		$ip_185 = "185.125.190.49"
		$ip_91 = "91.189.91.49"
		$ip_224 = "224.0.0.251"
		$domain_arpa = "10.100.168.192.in-addr.arpa"
		
		// Puertos comunes utilizados
		$port_22 = ":22"
		$port_80 = ":80"
		$port_123 = ":123"
		$port_161 = ":161"
		$port_443 = ":443"
		$port_873 = ":873"
		$port_9103 = ":9103"

	condition:
		// DetecciÃ³n por hash SHA256 especÃ­fico
		(
			hash.sha256(0,filesize) == "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba" or
			hash.sha256(0,filesize) == "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd" or
			hash.sha256(0,filesize) == "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
		) or
		// DetecciÃ³n por caracterÃ­sticas de comportamiento
		(
			($miname and $iptables1 and $iptables2 and $procnet) and
			(
				($dir1 and ($pass1 or $pass2 or $pass3 or $pass4)) or
				($ip_185 or $ip_91 or $ip_224 or $domain_arpa) or
				(2 of ($port_*))
			)
		)
}

rule Mirai_SHA256_Hash1 : MALW
{
	meta:
		description = "Mirai Botnet - Hash SHA256 especÃ­fico 1"
		author = "Jorge Felix Gonzalez Arias"
		date = "2025-07-14"
		version = "1.0"
		credits = "Basado en trabajo original de Felipe Molina / @felmoltor"
		SHA256 = "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba"

	condition:
		hash.sha256(0,filesize) == "57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba"
}

rule Mirai_SHA256_Hash2 : MALW
{
	meta:
		description = "Mirai Botnet - Hash SHA256 especÃ­fico 2"
		author = "Jorge Felix Gonzalez Arias"
		date = "2025-07-14"
		version = "1.0"
		credits = "Basado en trabajo original de Felipe Molina / @felmoltor"
		SHA256 = "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd"

	condition:
		hash.sha256(0,filesize) == "72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd"
}

rule Mirai_SHA256_Hash3 : MALW
{
	meta:
		description = "Mirai Botnet - Hash SHA256 especÃ­fico 3"
		author = "Jorge Felix Gonzalez Arias"
		date = "2025-07-14"
		version = "1.0"
		credits = "Basado en trabajo original de Felipe Molina / @felmoltor"
		SHA256 = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"

	condition:
		hash.sha256(0,filesize) == "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
}

rule Mirai_Network_Indicators : MALW
{
	meta:
		description = "Mirai Botnet - Indicadores de red especÃ­ficos"
		author = "Jorge Felix Gonzalez Arias"
		date = "2025-07-14"
		version = "1.0"
		credits = "Basado en trabajo original de Felipe Molina / @felmoltor"

	strings:
		$ip_1 = "185.125.190.49"
		$ip_2 = "91.189.91.49"
		$ip_3 = "224.0.0.251"
		$domain = "10.100.168.192.in-addr.arpa"
		
		// CaracterÃ­sticas generales de Mirai
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		($miname or $iptables1 or $procnet) and
		(
			$ip_1 or $ip_2 or $ip_3 or $domain
		)
}
