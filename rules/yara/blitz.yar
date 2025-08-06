import "pe"

rule MAL_Win_Blitz_Comprehensive : FILE
{
    meta:
        description = "Detects multiple components of the Blitz malware family, including droppers, downloaders, and the final bot payload. This rule identifies artifacts related to persistence, anti-analysis techniques, C2 communication, and specific bot identifiers."
        author = "bigbudda"
        date = "2025-08-06"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/blitz-malware-2025/"
        hash = "14467edd617486a1a42c6dab287ec4ae21409a5dc8eb46d77b853427b67d16d6"
        hash = "056fb07672dac83ef61c0b8b5bdc5e9f1776fc1d9c18ef6c3806e8fb545af78c"
        hash = "ae2f4c49f73f6d88b193a46cd22551bb31183ae6ee79d84be010d6acf9f2ee57"
        hash = "cacc1f36b3817e8b48fabbb4b4bd9d2f1949585c2f5170e3d2d04211861ef2ac"
        tags = "CRIME, BOT, DOWNLOADER, DROPPER, BLITZ, XMRIG, FILE"
        mitre_attack = "T1547.001, T1497.001, T1055, T1056.001, T1071.001, T1105"
        malware_family = "Blitz"

    strings:
        // --- Persistence Artifacts ---
        $p1 = "UserInitMprLogonScript" wide ascii
        $p2 = "EdgeUpdater" wide ascii // Value for HKCU Run key

        // --- Dropped File & Injection Target ---
        $f1 = "ieapfltr.dll" wide ascii // Downloader DLL name
        $f2 = "RuntimeBroker.exe" wide ascii // Bot injection target

        // --- Anti-Analysis Artifacts ---
        $a1 = "[ERR] Failed with code: 137" wide ascii
        $a2 = "\\\\?\\A3E64E55_fl" wide // ANY.RUN sandbox driver check

        // --- Bot-Specific Artifacts ---
        $b_mutex1 = "7611646b02ffd5de6cb3f41d0721f2ba" ascii // Blitz bot mutex
        $b_mutex2 = "9bdcf5f16cb8331241b2997ef88d2a67" ascii // XMRig mutex
        $b_log = "RestartManager.log" wide ascii // Keylogger output file

        // --- C2 Domains ---
        // These strings may cause FPs on their own, so they are used in combination with other indicators.
        $c1 = "swizxx-blitz-net.hf.space" ascii
        $c2 = "e445a00fffe335d6dac0ac0fe0a5accc-9591beae439b860-b5c7747.hf.space" ascii

    condition:
        // Must be a PE file under 5MB
        pe.is_pe and filesize < 5MB and
        (
            // Dropper detection: Requires persistence, anti-analysis, and the dropped DLL name
            (1 of ($p*)) and (1 of ($a*)) and $f1
            or
            // Bot/Downloader detection: Requires bot-specific artifacts and a C2 domain
            (2 of ($b_*)) and (1 of ($c*))
            or
            // High-confidence combination for the bot payload
            all of ($b_*)
            or
            // Combination for downloader/bot targeting RuntimeBroker
            $f2 and (1 of ($b_*)) and (1 of ($c*))
        )
}
