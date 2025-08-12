Claro, aquí tienes un informe de CTI basado en el documento "Entra Account Storm Campaign.pdf".

---

# **Informe de Inteligencia de Amenazas Cibernéticas (CTI): Entra Account Storm Campaign**

**TLP:GREEN**

## 1. Resumen Ejecutivo

La "Entra Account Storm Campaign" es una campaña de ciberataque dirigida contra cuentas de Microsoft Entra ID. El actor de amenazas, identificado como **Storm-0558**, utiliza ataques de `Password Spraying` desde infraestructura en la nube (principalmente AWS) para obtener acceso no autorizado. El objetivo principal es el espionaje y la exfiltración de datos sensibles, como correos electrónicos y documentos de SharePoint. La campaña, activa desde al menos junio de 2023 con picos de actividad a principios de 2025, afecta a una amplia gama de industrias a nivel mundial, destacando la vulnerabilidad inherente a las credenciales débiles y la necesidad de una monitorización de seguridad robusta en la nube.

| Atributo | Descripción |
| :--- | :--- |
| **Nombre de la Campaña** | Entra Account Storm Campaign |
| **Actor de Amenazas** | Storm-0558 |
| **Objetivo Principal** | Espionaje y exfiltración de datos (correos, archivos). |
| **Vector Principal** | Password Spraying (T1110.003) |
| **Periodo de Actividad** | Detectado desde junio de 2023, con un pico en enero-febrero de 2025. |
| **Impacto Potencial** | Robo de datos, escalada de privilegios, pérdida de confianza, sanciones regulatorias. |

## 2. Atribución y Motivación

*   **Actor de Amenazas:** Microsoft atribuye la campaña con **confianza media** a **Storm-0558**, un actor de amenazas basado en China. Aunque se han encontrado solapamientos mínimos con otros grupos como Violet Typhoon (APT31), Microsoft considera que Storm-0558 opera de forma independiente.
*   **Motivación:** El objetivo principal es el **espionaje**. El actor muestra un interés persistente en obtener acceso no autorizado a cuentas de correo y datos de organizaciones en sectores específicos para la recolección de inteligencia. Sus tácticas se centran en el robo de credenciales, phishing y ataques a tokens de OAuth.

## 3. Victimología

La campaña tiene un alcance global y se dirige a sectores que gestionan datos críticos.

*   **Industrias Afectadas:**
    *   Gobierno
    *   Organizaciones No Gubernamentales (ONG)
    *   Servicios de TI y Tecnología
    *   Defensa
    *   Telecomunicaciones
    *   Salud
    *   Energía, Petróleo y Gas
    *   Medios de comunicación
    *   Think Tanks

## 4. Tácticas, Técnicas y Procedimientos (TTPs) - Mapeo MITRE ATT&CK

| Táctica | Técnica (ID) | Sub-Técnica (ID) | Descripción |
| :--- | :--- | :--- | :--- |
| **Escalada de Privilegios** | Exploitation for Privilege Escalation (T1068) | | Los atacantes explotan vulnerabilidades de software para ejecutar código con permisos elevados. |
| **Escalada de Privilegios** | Access Token Manipulation (T1134) | | Manipulan tokens de acceso para ejecutar procesos en el contexto de seguridad de otro usuario (ej. SYSTEM). |
| **Acceso a Credenciales** | Brute Force (T1110) | Password Spraying (T1110.003) | Prueban una contraseña común contra múltiples cuentas para evitar bloqueos y explotar credenciales débiles. |

## 5. Infraestructura de Ataque

*   **Proveedor de Hosting:** La infraestructura de ataque se aloja predominantemente en **Amazon Web Services (AWS)**, utilizando el ASN **AS14618 (AMAZON-AES)**.
*   **Ubicación Geográfica de Nodos:**
    *   La mayoría de las direcciones IP están ubicadas en **Ashburn, Virginia, Estados Unidos**.
    *   Una dirección IP fue identificada en **Dublin, Irlanda**.
    *   Los servicios utilizados se identifican como servidores proxy públicos.

## 6. Indicadores de Compromiso (IoCs)

Se han identificado las siguientes direcciones IP como parte de la infraestructura de ataque de la campaña. Todas pertenecen a **AS14618 (AMAZON-AES)**.

| Indicador | Tipo | Descripción |
| :--- | :--- | :--- |
| `44.218.97.232` | IP Address | Nodo de ataque (Ashburn, US) |
| `44.220.31.157` | IP Address | Nodo de ataque (Ashburn, US) |
| `44.206.7.122` | IP Address | Nodo de ataque (Ashburn, US) |
| `44.210.64.196` | IP Address | Nodo de ataque (Ashburn, US) |
| `44.212.180.197` | IP Address | Nodo de ataque (Ashburn, US) |
| `3.238.215.143` | IP Address | Nodo de ataque (Ashburn, US) |
| `44.206.7.134` | IP Address | Nodo de ataque (Ashburn, US) |
| `3.216.140.96` | IP Address | Nodo de ataque (Ashburn, US) |
| `3.255.18.223` | IP Address | Nodo de ataque (Dublin, IE) |
| `44.210.66.100` | IP Address | Nodo de ataque (Ashburn, US) |

## 7. Impacto y Riesgo

*   **Exfiltración de Datos:** Los atacantes pueden robar una amplia gama de información, incluyendo correos electrónicos, archivos de SharePoint/OneDrive (propiedad intelectual, datos financieros, PII), conversaciones de Teams y datos de aplicaciones de terceros conectadas vía SSO (Salesforce, Workday, GitHub).
*   **Escalada de Privilegios:** El riesgo es **alto**. Los atacantes pueden asignar roles de administrador global, añadir credenciales a aplicaciones o modificar la configuración de federación para obtener control total sobre el tenant.
*   **Impacto Reputacional y Regulatorio:** Un ataque exitoso puede llevar a una pérdida de confianza del cliente, daño a la marca, multas bajo regulaciones como GDPR o CCPA, y litigios costosos.

## 8. Detección

La detección se centra en el análisis de los logs `AuditLogs` y `SigninLogs` de Microsoft Entra ID.

*   **Señales Clave en `SigninLogs`:**
    *   **Password Spraying:** Gran número de inicios de sesión fallidos (`ResultType: 50126`) desde una misma IP para múltiples usuarios.
    *   **Viaje Imposible:** Inicios de sesión exitosos para un usuario desde ubicaciones geográficamente imposibles.
    *   **Acceso desde IPs Anónimas:** Inicios de sesión desde TOR o IPs maliciosas conocidas.
    *   **Protocolos Heredados:** Uso de IMAP/POP3/SMTP que no soportan MFA.

*   **Eventos Clave en `AuditLogs`:**
    *   **`Add member to role`:** Asignación de roles privilegiados (Global Administrator, etc.).
    *   **`Update Application - Credentials`:** Adición de nuevas credenciales a una aplicación o Service Principal.
    *   **`Consent to application`:** Consentimiento a aplicaciones sospechosas o desconocidas.

### Consulta KQL para Detección

La siguiente consulta KQL para Microsoft Sentinel puede ayudar a detectar TTPs clave de esta campaña.

```kql
// This query combines multiple detection techniques for Microsoft Entra ID
// privilege escalation and password spraying attacks.
// It is designed to identify several TTPs associated with the "Entra
// Account Storm" campaign.
// Define a lookback period for the search.
let lookback = 1d;
// Part 1: Detects the assignment of highly privileged roles in Entra ID.
// Legitimate administrative activity can trigger this, so review the actor
// and target context.
let privilegedRoleAssignments = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "RoleManagement" and OperationName == "Add member to role"
| extend RoleDisplayName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where RoleDisplayName has_any (
    "Global Administrator",
    "Privileged Role Administrator",
    "Cloud Application Administrator",
    "Application Administrator",
    "Hybrid Identity Administrator"
)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project
    TimeGenerated,
    DetectionType = "Privileged Role Assigned",
    Actor,
    TargetUser,
    RoleAssigned = RoleDisplayName,
    Description = strcat("User '", Actor, "' assigned role '", RoleAssigned, "' to user '", TargetUser, "'.")
| extend IPAddress = tostring(InitiatedBy.user.ipAddress);
// Part 2: Detects when new credentials are added to an Application or Service Principal.
// This is a key persistence and escalation technique.
let credentialAddition = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Update Application - Credentials", "Add service principal credentials", "Update service principal credentials")
| extend TargetName = tostring(TargetResources[0].displayName)
| extend TargetId = tostring(TargetResources[0].id)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project
    TimeGenerated,
    DetectionType = "Credentials Added to Principal",
    Actor,
    TargetName,
    TargetId,
    Description = strcat("User '", Actor, "' added new credentials to principal '", TargetName, "'.")
| extend IPAddress = tostring(InitiatedBy.user.ipAddress);
// Part 3: Detects password spraying attacks.
// A single IP attempting to log in as many different users with a high failure rate.
// Tune the 'userThreshold' based on your environment's baseline.
let userThreshold = 15;
let passwordSpraying = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 50126 // Error code for "Invalid username or password"
| summarize
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailedUserCount = dcount(UserPrincipalName),
    FailedUsers = make_set(UserPrincipalName, 100)
by IPAddress, UserAgent
| where FailedUserCount > userThreshold
// Optional: Check for any successful logins from the same IP to see if the spray was partially successful.
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | summarize SuccessfulLogins = dcount(UserPrincipalName) by IPAddress
) on IPAddress
| project
    TimeGenerated = StartTime,
    DetectionType = "Password Spraying Attack",
    IPAddress,
    UserAgent,
    FailedUserCount,
    SuccessfulLogins = todouble(SuccessfulLogins),
    Description = strcat("Potential password spray from IP '", IPAddress, "' targeting ", tostring(FailedUserCount), " users.");
// Union all detection parts into a single result set.
union privilegedRoleAssignments, credentialAddition, passwordSpraying
| project-rename
    Principal = Actor,
    Entity = TargetUser
| project
    TimeGenerated,
    DetectionType,
    Principal,
    Entity,
    IPAddress,
    Description
```

## 9. Medidas de Mitigación

*(La sección de mitigación estaba incompleta en el documento de origen. Se recomienda seguir las mejores prácticas de seguridad de Microsoft para Entra ID).*

*   **Para T1068 (Explotación para Escalada de Privilegios):**
    *   Implementar un programa robusto de gestión de parches para corregir vulnerabilidades conocidas de manera oportuna.
    *   Utilizar controles de aplicación para restringir la ejecución de software no autorizado.
*   **Para T1110.003 (Password Spraying):**
    *   Implementar y forzar la **Autenticación Multifactor (MFA)** para todos los usuarios.
    *   Utilizar **Microsoft Entra Password Protection** para prohibir contraseñas débiles y comunes.
    *   Bloquear protocolos de autenticación heredados que no soporten MFA.
*   **Para T1134 (Manipulación de Tokens de Acceso):**
    *   Aplicar el principio de **mínimo privilegio** a las cuentas de usuario y servicio.
    *   Monitorizar la creación y modificación de tokens y el uso de APIs de suplantación.
