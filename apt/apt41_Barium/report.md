# APT41 - Winnti o Barium

## 1. Identificación General

* **Nombre de la Campaña:** APT41 dust, C0017
* **Grupo APT:** APT41 (también conocido como: Amoeba, BARIUM, BRONZE ATLAS, BRONZE EXPORT, Blackfly, Brass Typhoon, Double Dragon, Earth Baku, G0044, G0096, Grayfly, HOODOO, LEAD, Leopard Typhoon, Red Kelpie, TA415, TG-2633, WICKED PANDA, WICKED SPIDER, Winnti)
* **Fecha de Actividad:** Primera campaña en mayo de 2021 y la última en junio de 2024.
* **Motivación:** Grupo de espionaje patrocinado por el estado chino que también lleva a cabo operaciones con motivaciones financieras (cibercrimen).
* **Victimología:** Proveedores de telecomunicaciones en Estados Unidos, Australia, China (Tíbet), Chile, India, Indonesia, Malasia, Pakistán, Singapur, Corea del Sur, Taiwán y Tailandia. Han atacado diversas industrias como salud, telecomunicaciones, tecnología, finanzas, educación, comercio minorista y videojuegos en 14 países.

## 2. Objetivos y Contexto

* **Sectores Atacados:** Como se mencionó en la victimología, APT41 ha dirigido a proveedores de telecomunicaciones y otras industrias como la salud, tecnología, finanzas, educación, comercio minorista y videojuegos.
* **Impactos y Declaraciones Públicas:** La información explícita sobre impactos económicos, políticos o tecnológicos específicos, así como declaraciones públicas de empresas o gobiernos, no está detallada en las fuentes proporcionadas.

## 3. Vectores de Ataque

* **Acceso Inicial:**
    * **Cuentas Comprometidas:** APT41 ha utilizado cuentas válidas robadas para el acceso inicial y otras operaciones (`T1078`).
    * **Explotación de Vulnerabilidades:** Se ha observado el uso del exploit ofuscado BADPOTATO para escalar privilegios locales.
* **Otros Vectores:** La información específica sobre spear-phishing con adjuntos PDF/Word maliciosos o el uso de CVEs específicas como vector de acceso inicial no se encuentra detallada en las fuentes proporcionadas.

## 4. Malware y Herramientas Usadas

APT41 utiliza un amplio arsenal de herramientas y malware, incluyendo:

| Software/Herramienta | Descripción |
| :------------------- | :---------- |
| Acunetix | Usado para escaneo de vulnerabilidades SQL injection. |
| ADORE.XSEC | Backdoor aprovechado a través de un script oculto. |
| Adore-NG | Rootkit utilizado. |
| ANTSWORD | Web shell para persistencia. |
| BADPOTATO | Exploit ofuscado con ConfuserEx para escalada de privilegios locales. |
| BLUEBEAM | Web shell para persistencia. |
| BrowserGhost | Herramienta para obtener credenciales de navegadores. |
| CLASSFON | Herramienta para proxy de comunicaciones de red. |
| Cobalt Strike | Usado para despliegue de malware y persistencia (BEACON loader). |
| ConfuserEx | Obfuscador usado con el exploit BADPOTATO. |
| CRACKSHOT | Malware conocido de APT41. |
| DUSTPAN | Dropper y loader para descifrar payloads incrustados, a veces disfrazado de binario legítimo. |
| DUSTTRAP | Malware y componentes firmados con certificados robados, ejecutado vía secuestro de orden de búsqueda de DLL. |
| Encryptor RaaS | Ransomware usado para cifrar archivos. |
| HIGHNOON | Variedad de malware para enumerar sesiones RDP activas. |
| JexBoss | Herramienta para identificar vulnerabilidades en aplicaciones Java. |
| KEYPLUG | Backdoor de Windows con resolvers dead drop actualizados frecuentemente. |
| LOWKEY.PASSIVE | Backdoor pasivo configurado para disfrazar el tráfico web. |
| Mimikatz | Usado para volcar hashes de contraseñas de la memoria. |
| MiPing | Usado para descubrir sistemas activos en la red de la víctima. |
| NATBypass | Usado para evadir restricciones de firewall y acceder a sistemas comprometidos vía RDP. |
| PINEGROVE | Usado para recolectar información de sistemas locales y bases de datos. |
| POISONPLUG | Malware conocido de APT41. |
| PowerSploit | Usado para persistencia vía WMI. |
| Procdump | Usado para volcar hashes de contraseñas de la memoria. |
| Speculoos Backdoor | Backdoor utilizado por APT41. |
| SQLULDR2 | Usado para recolectar datos de bases de datos Oracle. |
| TIDYELF | Malware que carga el componente principal de WINTERLOVE inyectándolo en `iexplore.exe`. |
| WIDETONE | Variedad de malware para realizar escaneos de puertos en subredes específicas. |
| Windows Credential Editor | Usado para volcar hashes de contraseñas de la memoria. |
| WINTERLOVE | Componente principal cargado por TIDYELF. |
| Winnti | Usado para Windows, cargado vía secuestro de orden de búsqueda de DLL. |
| YSoSerial.NET | Herramienta de explotación de deserialización. |

* **Técnicas Comunes:**
    * **DLL Sideloading:** Observado con malware como `Winnti` que se carga a través del secuestro de orden de búsqueda de DLL.
    * **Living off the Land Binaries (LOLBins):** Aunque no se menciona explícitamente "LOLBins", el grupo utiliza herramientas incorporadas del sistema como comandos `net` y `makecab.exe` para diversas operaciones.
* **Backdoors Específicas:** Las herramientas como Voldemort, Spark o HealthKick no se mencionan específicamente en las fuentes proporcionadas.

## 5. TTPs (MITRE ATT&CK Mapeados)

APT41 emplea una variedad de TTPs para llevar a cabo sus operaciones, mapeadas a MITRE ATT&CK (versión v4.1 - attack v17):

* **Initial Access**
    * `T1078: Cuentas Válidas` - El uso de cuentas válidas comprometidas para el acceso.
* **Execution**
    * `T1047: Ejecución a través de Windows Management Instrumentation` - Uso de WMI para la ejecución de comandos (WMIEXEC) y persistencia (PowerSploit).
    * `T1059.003: Shell de Comandos de Windows` - Uso de `cmd.exe` para la ejecución de comandos.
* **Persistence**
    * `T1547.001: Entrada de Registro Run Keys / Startup Folder` - Uso de la clave `Run` del registro para la ejecución automática.
* **Privilege Escalation**
    * `T1134: Manipulación de Token` - Uso del exploit BADPOTATO ofuscado para escalada de privilegios locales a `NT AUTHORITY\SYSTEM`.
* **Defense Evasion**
    * `T1027.002: Obfuscación de Archivos o Información` - Empleo de la ofuscación de cadenas.
    * `T1218.011: Ejecución de Binarios Firmados de Proxy: DLL Sideloading` - Técnica observada con malware como `Winnti`.
* **Credential Access**
    * `T1003: Acceso a Credenciales` - Uso de herramientas como Mimikatz, `pwdump` y Windows Credential Editor para volcar hashes de contraseñas.
* **Discovery**
    * `T1087.001: Cuentas de Dominio` - Enumeración de usuarios administradores de dominio.
    * `T1087.002: Cuentas Locales` - Enumeración de grupos de administradores locales.
* **Collection**
    * `T1005: Datos del Sistema Local` - Uso de herramientas como PINEGROVE para recolectar información de sistemas locales y bases de datos.
    * `T1560.001: Archivos Comprimidos` - Uso de `makecab.exe` para comprimir datos.
* **Lateral Movement**
    * `T1021.001: Escritorio Remoto` - Uso de RDP para el acceso a sistemas comprometidos.
* **Command and Control**
    * `T1071.001: Protocolos de Capa de Aplicación Web` - Uso de sitios web legítimos (GitHub, Pastebin, Microsoft TechNet) como "dead drop resolvers" para C2.
    * `T1090: Proxy` - Uso de la herramienta de proxy MiPing para comunicaciones de red.

Las técnicas T1566.001 (phishing attachment) y T1041 (Exfil over C2 Channel) no están explícitamente detalladas en el JSON o PDF proporcionado con un ID de MITRE ATT&CK asociado a APT41.

## 6. Infraestructura C2

* **Métodos de Conexión:** APT41 ha utilizado sitios web legítimos como GitHub, Pastebin y Microsoft TechNet como "dead drop resolvers" (DDR) para sus comunicaciones de Comando y Control (C2), actualizando frecuentemente las publicaciones. Las comunicaciones implican protocolos de capa de aplicación web como HTTP.
* **Certificados TLS:** El grupo ha utilizado certificados revocados en algunas de sus operaciones. Las reglas YARA incluyen firmas para estos certificados.
* **IPs Públicas, Puertos Abiertos, Dominios Específicos, GeoIP/Reputación:** La información detallada sobre IPs públicas específicas, puertos abiertos, dominios maliciosos exclusivos de C2, así como datos de GeoIP o reputación de IP, no se encuentra en las fuentes proporcionadas.

## 7. Indicadores de Compromiso (IoCs)

### Hashes

* **POISONPLUG:** `70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e`, `0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb`, `2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd`, `5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90`, `f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661`, `3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f`
* **POISONPLUG SHADOW:** `462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8`
* **CRACKSHOT:** `993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31`
* **HIGHNOON:** `63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7`, `4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213`
* **HIGHNOON.BIN:** `490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994`, `79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d`, `c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d`
* **Speculoos Backdoor:** `6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167`, `99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28`
* **`7.dll.exe`:** `151257e9dfda476cdafd9983266ad3255104d72a66f9265caa8417a5fe1df5d7`

### Dominios y URLs

* Sitios web legítimos usados para C2 (dead drop resolvers - DDR): GitHub, Pastebin, Microsoft TechNet.

### Nombres de Archivo Sospechosos

* `ma_lockdown_service.dll`
* `acbde.dll`
* `TSMSISrv.DLL`
* `tcpview.exe`
* `procmon64.exe`
* `netmon.exe`
* `MiniSniffer.exe`
* `smsniff.exe`
* `workdll64.dll`
* `PlusDll.dll`
* `ShutDownEvent.dll`
* `badshell`
* `hw.physmem`
* `7.dll.exe`

### Rutas Comunes

* `\\Fonts\\Error.log`
* `\\svchost.exe`
* `\\Device\\PORTLESS_DeviceName`
* `%s%s\\Security`
* `%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings`
* `%s%s\\Enum`
* `H:\\RBDoor\\` (PDB path)
* `\\RbDoorX64.pdb` (PDB path)
* `%s\\NtKlRes.dat`
* `/usr/sbin/config.bak`
* `nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS` (versión inversa de `Software\Microsoft\Windows\CurrentVersion\Run`)

### Cadenas Sospechosas y Firmas

Las reglas YARA proporcionadas en `apt41.yar` contienen una variedad de cadenas sospechosas y otras firmas que pueden ser utilizadas para la detección de la actividad de APT41.

## 8. Detección

* **Reglas YARA:** Reglas YARA personalizadas para ejecutables y payloads específicos de APT41 están disponibles en el archivo `apt41.yar` en este repositorio. Estas reglas permiten la detección basada en firmas de los artefactos del grupo.
* **Comportamiento Observable:** Los TTPs mapeados a MITRE ATT&CK ofrecen una guía para el comportamiento observable, incluyendo procesos, modificaciones de claves de registro (como `Run` keys), tráfico de red inusual (conexiones a sitios legítimos usados como C2), y uso de herramientas del sistema para tareas maliciosas.
* **Reglas Sigma, Snort/Suricata:** La información para generar reglas Sigma o Snort/Suricata no se encuentra explícitamente en las fuentes proporcionadas.

## 9. Mitigación y Defensa

La información detallada sobre estrategias específicas de mitigación y defensa (como bloqueo de phishing, hardening de endpoints, procedimientos de respuesta a incidentes o blocklists de IoCs) no se encuentra explícitamente en las fuentes proporcionadas. No obstante, las reglas YARA e IoCs pueden utilizarse para alimentar sistemas de seguridad para la detección y contención.

## 10. Referencias

* [FireEye: APT41 Dual Espionage and Cyber Crime Operation](https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html)
* [Palo Alto Networks Unit 42: APT41 Using New Speculoos Backdoor to Target Organizations Globally](https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/)
* [MITRE ATT&CK: Group G0096 (APT41)](https://attack.mitre.org/groups/G0096/)
* [Mandiant: APT41 - Dual Operation](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf)
* fbi.gov
* resecurity.com
* malpedia
* virustotal
* threat.zone
* abuse.ch
