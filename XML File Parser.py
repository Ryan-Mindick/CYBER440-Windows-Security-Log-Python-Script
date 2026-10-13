#!/usr/bin/env python3
"""
event_log_report.py - Decode large Windows event log XML exports into ONE
easy-to-read HTML report that opens in any web browser (Chrome, Edge, Firefox,
Safari). No extra packages needed: standard library only, Python 3.7+.

WHAT IT DOES
  * Streams through very large XML files (hundreds of thousands of lines).
  * Describes every event using a built-in reference covering the full Windows
    Security audit log, plus common System, RDP, PowerShell, Task Scheduler,
    Defender and Sysmon events.
  * Decodes logon types, NTSTATUS failure codes, Kerberos result codes,
    encryption / pre-auth types, %%-style message codes and well-known SIDs.
  * Marks each event as Audit Success or Audit Failure.

HOW TO POINT IT AT YOUR FILE (pick one)
  1. Set INPUT_PATH below, then run:     python event_log_report.py
  2. Pass it on the command line:         python event_log_report.py "C:\\logs\\security.xml"
  3. Leave INPUT_PATH empty and run with no arguments; a file picker opens.
  A FOLDER path processes every .xml file inside it into one report.

LOOK UP A CODE WITHOUT A FILE
  python event_log_report.py --lookup 4625
  python event_log_report.py --lookup 0xC000006A

OUTPUT (saved next to the input)
  <name>_report.html   ONE file containing:
                         Summary - totals and breakdown tables
                         Events  - every event in a searchable, sortable,
                                   filterable table (100 rows per page)
  Click any row in a summary table to see just those events.
"""

# ----------------------------------------------------------------------------
# EDIT THIS: path to your XML file or a folder of XML files.
# Windows example:  r"C:\Users\YourName\Downloads\security_log.xml"
# Mac example:      "/Users/yourname/Downloads/security_log.xml"
INPUT_PATH = r"C:\Users\rjmin\Downloads\XML Data"
OPEN_WHEN_DONE = True      # open the report in your browser when finished
EXCLUDE_ACCOUNT_PREFIX = "AFC"   # "Top 25 accounts" skips accounts starting with this (not case-sensitive)

# ---- Suspicious activity settings ------------------------------------------
# Event times are stored in UTC. Set the offset of the time zone the computers
# are in so "off-hours" means their local night. US Eastern: -5 in winter, -4 in summer.
UTC_OFFSET_HOURS = 0
OFF_HOURS_START = 0              # local hour off-hours begin (0 = midnight)
OFF_HOURS_END = 6                # local hour off-hours end (6 = 6 AM)
BRUTE_FORCE_THRESHOLD = 5        # failed logons on one account ...
BRUTE_FORCE_WINDOW_MIN = 10      # ... within this many minutes
SPRAY_ACCOUNTS = 5               # one source failing on this many different accounts ...
SPRAY_WINDOW_MIN = 30            # ... within this many minutes
SUCCESS_AFTER_FAIL_COUNT = 3     # failures followed by a success ...
SUCCESS_AFTER_FAIL_MIN = 30      # ... within this many minutes
CHURN_THRESHOLD = 60             # logon/logoff events by one person ...
CHURN_WINDOW_MIN = 10            # ... within this many minutes
MANY_SOURCES = 5                 # one person logging on from this many sources in an hour
KERBEROAST_SERVICES = 5          # weak-encryption tickets for this many different services
# ----------------------------------------------------------------------------

import argparse
import html
import json
import re
import sys
import time
import webbrowser
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


# ============================================================================
#  REFERENCE DATA
# ============================================================================

# ---- Security log: Microsoft-Windows-Security-Auditing and Eventlog (1100-series)
SECURITY_EVENTS = {
    # Event log service
    1100: "The event logging service has shut down",
    1101: "Audit events have been dropped by the transport",
    1102: "The audit log was cleared",
    1104: "The security log is now full",
    1105: "Event log automatic backup",
    1108: "The event logging service encountered an error",
    # System
    4608: "Windows is starting up",
    4609: "Windows is shutting down",
    4610: "An authentication package has been loaded by the Local Security Authority",
    4611: "A trusted logon process has been registered with the Local Security Authority",
    4612: "Internal resources allocated for queuing audit messages were exhausted; some audits lost",
    4614: "A notification package has been loaded by the Security Account Manager",
    4615: "Invalid use of LPC port",
    4616: "The system time was changed",
    4618: "A monitored security event pattern has occurred",
    4621: "Administrator recovered system from CrashOnAuditFail",
    4622: "A security package has been loaded by the Local Security Authority",
    # Logon / logoff
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4626: "User/Device claims information",
    4627: "Group membership information",
    4634: "An account was logged off",
    4646: "IKE DoS-prevention mode started",
    4647: "User initiated logoff",
    4648: "A logon was attempted using explicit credentials",
    4649: "A replay attack was detected",
    4650: "An IPsec Main Mode security association was established (no certificate auth)",
    4651: "An IPsec Main Mode security association was established (certificate auth)",
    4652: "An IPsec Main Mode negotiation failed",
    4653: "An IPsec Main Mode negotiation failed",
    4654: "An IPsec Quick Mode negotiation failed",
    4655: "An IPsec Main Mode security association ended",
    # Object access
    4656: "A handle to an object was requested",
    4657: "A registry value was modified",
    4658: "The handle to an object was closed",
    4659: "A handle to an object was requested with intent to delete",
    4660: "An object was deleted",
    4661: "A handle to an object was requested (SAM / directory service)",
    4662: "An operation was performed on an object",
    4663: "An attempt was made to access an object",
    4664: "An attempt was made to create a hard link",
    4665: "An attempt was made to create an application client context",
    4666: "An application attempted an operation",
    4667: "An application client context was deleted",
    4668: "An application was initialized",
    4670: "Permissions on an object were changed",
    4671: "An application attempted to access a blocked ordinal through the TBS",
    # Privilege use
    4672: "Special privileges assigned to new logon",
    4673: "A privileged service was called",
    4674: "An operation was attempted on a privileged object",
    4675: "SIDs were filtered",
    # Process tracking
    4688: "A new process has been created",
    4689: "A process has exited",
    4690: "An attempt was made to duplicate a handle to an object",
    4691: "Indirect access to an object was requested",
    4692: "Backup of data protection master key was attempted",
    4693: "Recovery of data protection master key was attempted",
    4694: "Protection of auditable protected data was attempted",
    4695: "Unprotection of auditable protected data was attempted",
    4696: "A primary token was assigned to process",
    4697: "A service was installed in the system",
    4698: "A scheduled task was created",
    4699: "A scheduled task was deleted",
    4700: "A scheduled task was enabled",
    4701: "A scheduled task was disabled",
    4702: "A scheduled task was updated",
    4703: "A token right was adjusted",
    # Policy change
    4704: "A user right was assigned",
    4705: "A user right was removed",
    4706: "A new trust was created to a domain",
    4707: "A trust to a domain was removed",
    4709: "IPsec Services was started",
    4710: "IPsec Services was disabled",
    4711: "PAStore Engine event (IPsec policy)",
    4712: "IPsec Services encountered a potentially serious failure",
    4713: "Kerberos policy was changed",
    4714: "Encrypted data recovery policy was changed",
    4715: "The audit policy (SACL) on an object was changed",
    4716: "Trusted domain information was modified",
    4717: "System security access was granted to an account",
    4718: "System security access was removed from an account",
    4719: "System audit policy was changed",
    # Account management
    4720: "A user account was created",
    4722: "A user account was enabled",
    4723: "An attempt was made to change an account's password",
    4724: "An attempt was made to reset an account's password",
    4725: "A user account was disabled",
    4726: "A user account was deleted",
    4727: "A security-enabled global group was created",
    4728: "A member was added to a security-enabled global group",
    4729: "A member was removed from a security-enabled global group",
    4730: "A security-enabled global group was deleted",
    4731: "A security-enabled local group was created",
    4732: "A member was added to a security-enabled local group",
    4733: "A member was removed from a security-enabled local group",
    4734: "A security-enabled local group was deleted",
    4735: "A security-enabled local group was changed",
    4737: "A security-enabled global group was changed",
    4738: "A user account was changed",
    4739: "Domain Policy was changed",
    4740: "A user account was locked out",
    4741: "A computer account was created",
    4742: "A computer account was changed",
    4743: "A computer account was deleted",
    4744: "A security-disabled local group was created",
    4745: "A security-disabled local group was changed",
    4746: "A member was added to a security-disabled local group",
    4747: "A member was removed from a security-disabled local group",
    4748: "A security-disabled local group was deleted",
    4749: "A security-disabled global group was created",
    4750: "A security-disabled global group was changed",
    4751: "A member was added to a security-disabled global group",
    4752: "A member was removed from a security-disabled global group",
    4753: "A security-disabled global group was deleted",
    4754: "A security-enabled universal group was created",
    4755: "A security-enabled universal group was changed",
    4756: "A member was added to a security-enabled universal group",
    4757: "A member was removed from a security-enabled universal group",
    4758: "A security-enabled universal group was deleted",
    4759: "A security-disabled universal group was created",
    4760: "A security-disabled universal group was changed",
    4761: "A member was added to a security-disabled universal group",
    4762: "A member was removed from a security-disabled universal group",
    4763: "A security-disabled universal group was deleted",
    4764: "A group's type was changed",
    4765: "SID History was added to an account",
    4766: "An attempt to add SID History to an account failed",
    4767: "A user account was unlocked",
    # Account logon (Kerberos / NTLM)
    4768: "A Kerberos authentication ticket (TGT) was requested",
    4769: "A Kerberos service ticket was requested",
    4770: "A Kerberos service ticket was renewed",
    4771: "Kerberos pre-authentication failed",
    4772: "A Kerberos authentication ticket request failed",
    4773: "A Kerberos service ticket request failed",
    4774: "An account was mapped for logon",
    4775: "An account could not be mapped for logon",
    4776: "The computer attempted to validate the credentials for an account (NTLM)",
    4777: "The domain controller failed to validate the credentials for an account",
    4778: "A session was reconnected to a Window Station",
    4779: "A session was disconnected from a Window Station",
    4780: "The ACL was set on accounts which are members of administrators groups",
    4781: "The name of an account was changed",
    4782: "The password hash of an account was accessed",
    4783: "A basic application group was created",
    4784: "A basic application group was changed",
    4785: "A member was added to a basic application group",
    4786: "A member was removed from a basic application group",
    4787: "A non-member was added to a basic application group",
    4788: "A non-member was removed from a basic application group",
    4789: "A basic application group was deleted",
    4790: "An LDAP query group was created",
    4791: "An LDAP query group was changed",
    4792: "An LDAP query group was deleted",
    4793: "The Password Policy Checking API was called",
    4794: "An attempt was made to set the Directory Services Restore Mode administrator password",
    4797: "An attempt was made to query the existence of a blank password for an account",
    4798: "A user's local group membership was enumerated",
    4799: "A security-enabled local group membership was enumerated",
    4800: "The workstation was locked",
    4801: "The workstation was unlocked",
    4802: "The screen saver was invoked",
    4803: "The screen saver was dismissed",
    4816: "RPC detected an integrity violation while decrypting an incoming message",
    4817: "Auditing settings on object were changed",
    4818: "Proposed Central Access Policy does not grant the same access as the current policy",
    4819: "Central Access Policies on the machine have been changed",
    4820: "A Kerberos TGT was denied because the device does not meet access control restrictions",
    4821: "A Kerberos service ticket was denied because the user/device does not meet access control restrictions",
    4822: "NTLM authentication failed because the account was a member of the Protected Users group",
    4823: "NTLM authentication failed because access control restrictions are required",
    4824: "Kerberos pre-authentication using DES or RC4 failed because the account is in Protected Users",
    4825: "A user was denied access to Remote Desktop (not in Remote Desktop Users / Administrators)",
    4826: "Boot Configuration Data loaded",
    4830: "SID History was removed from an account",
    4864: "A namespace collision was detected",
    4865: "A trusted forest information entry was added",
    4866: "A trusted forest information entry was removed",
    4867: "A trusted forest information entry was modified",
    # Certificate Services
    4868: "The certificate manager denied a pending certificate request",
    4869: "Certificate Services received a resubmitted certificate request",
    4870: "Certificate Services revoked a certificate",
    4871: "Certificate Services received a request to publish the certificate revocation list (CRL)",
    4872: "Certificate Services published the certificate revocation list (CRL)",
    4873: "A certificate request extension changed",
    4874: "One or more certificate request attributes changed",
    4875: "Certificate Services received a request to shut down",
    4876: "Certificate Services backup started",
    4877: "Certificate Services backup completed",
    4878: "Certificate Services restore started",
    4879: "Certificate Services restore completed",
    4880: "Certificate Services started",
    4881: "Certificate Services stopped",
    4882: "The security permissions for Certificate Services changed",
    4883: "Certificate Services retrieved an archived key",
    4884: "Certificate Services imported a certificate into its database",
    4885: "The audit filter for Certificate Services changed",
    4886: "Certificate Services received a certificate request",
    4887: "Certificate Services approved a certificate request and issued a certificate",
    4888: "Certificate Services denied a certificate request",
    4889: "Certificate Services set the status of a certificate request to pending",
    4890: "The certificate manager settings for Certificate Services changed",
    4891: "A configuration entry changed in Certificate Services",
    4892: "A property of Certificate Services changed",
    4893: "Certificate Services archived a key",
    4894: "Certificate Services imported and archived a key",
    4895: "Certificate Services published the CA certificate to Active Directory",
    4896: "One or more rows have been deleted from the certificate database",
    4897: "Role separation enabled",
    4898: "Certificate Services loaded a template",
    4899: "A Certificate Services template was updated",
    4900: "Certificate Services template security was updated",
    # Audit policy
    4902: "The Per-user audit policy table was created",
    4904: "An attempt was made to register a security event source",
    4905: "An attempt was made to unregister a security event source",
    4906: "The CrashOnAuditFail value has changed",
    4907: "Auditing settings on object were changed",
    4908: "Special Groups Logon table modified",
    4909: "The local policy settings for the TBS were changed",
    4910: "The group policy settings for the TBS were changed",
    4911: "Resource attributes of the object were changed",
    4912: "Per User Audit Policy was changed",
    4913: "Central Access Policy on the object was changed",
    # Directory service replication
    4928: "An Active Directory replica source naming context was established",
    4929: "An Active Directory replica source naming context was removed",
    4930: "An Active Directory replica source naming context was modified",
    4931: "An Active Directory replica destination naming context was modified",
    4932: "Synchronization of a replica of an Active Directory naming context has begun",
    4933: "Synchronization of a replica of an Active Directory naming context has ended",
    4934: "Attributes of an Active Directory object were replicated",
    4935: "Replication failure begins",
    4936: "Replication failure ends",
    4937: "A lingering object was removed from a replica",
    # Windows Firewall
    4944: "The following policy was active when the Windows Firewall started",
    4945: "A rule was listed when the Windows Firewall started",
    4946: "A rule was added to the Windows Firewall exception list",
    4947: "A rule was modified in the Windows Firewall exception list",
    4948: "A rule was deleted from the Windows Firewall exception list",
    4949: "Windows Firewall settings were restored to the default values",
    4950: "A Windows Firewall setting has changed",
    4951: "A Windows Firewall rule was ignored (major version number not recognized)",
    4952: "Parts of a Windows Firewall rule were ignored (minor version number not recognized)",
    4953: "A Windows Firewall rule was ignored because it could not be parsed",
    4954: "Windows Firewall Group Policy settings changed; new settings applied",
    4956: "Windows Firewall has changed the active profile",
    4957: "Windows Firewall did not apply the following rule",
    4958: "Windows Firewall did not apply a rule that referred to items not configured on this computer",
    # IPsec
    4960: "IPsec dropped an inbound packet that failed an integrity check",
    4961: "IPsec dropped an inbound packet that failed a replay check",
    4962: "IPsec dropped an inbound packet that failed a replay check (sequence number too low)",
    4963: "IPsec dropped an inbound clear text packet that should have been secured",
    4964: "Special groups have been assigned to a new logon",
    4965: "IPsec received a packet with an incorrect Security Parameter Index (SPI)",
    4976: "During Main Mode negotiation, IPsec received an invalid negotiation packet",
    4977: "During Quick Mode negotiation, IPsec received an invalid negotiation packet",
    4978: "During Extended Mode negotiation, IPsec received an invalid negotiation packet",
    4979: "IPsec Main Mode and Extended Mode security associations were established",
    4980: "IPsec Main Mode and Extended Mode security associations were established",
    4981: "IPsec Main Mode and Extended Mode security associations were established",
    4982: "IPsec Main Mode and Extended Mode security associations were established",
    4983: "An IPsec Extended Mode negotiation failed",
    4984: "An IPsec Extended Mode negotiation failed",
    4985: "The state of a transaction has changed",
    5024: "The Windows Firewall Service has started successfully",
    5025: "The Windows Firewall Service has been stopped",
    5027: "The Windows Firewall Service was unable to retrieve the security policy from local storage",
    5028: "The Windows Firewall Service was unable to parse the new security policy",
    5029: "The Windows Firewall Service failed to initialize the driver",
    5030: "The Windows Firewall Service failed to start",
    5031: "The Windows Firewall Service blocked an application from accepting incoming connections",
    5032: "Windows Firewall was unable to notify the user that it blocked an application",
    5033: "The Windows Firewall Driver has started successfully",
    5034: "The Windows Firewall Driver has been stopped",
    5035: "The Windows Firewall Driver failed to start",
    5037: "The Windows Firewall Driver detected a critical runtime error and is terminating",
    5038: "Code integrity determined that the image hash of a file is not valid",
    5039: "A registry key was virtualized",
    5040: "An IPsec Authentication Set was added",
    5041: "An IPsec Authentication Set was modified",
    5042: "An IPsec Authentication Set was deleted",
    5043: "An IPsec Connection Security Rule was added",
    5044: "An IPsec Connection Security Rule was modified",
    5045: "An IPsec Connection Security Rule was deleted",
    5046: "An IPsec Crypto Set was added",
    5047: "An IPsec Crypto Set was modified",
    5048: "An IPsec Crypto Set was deleted",
    5049: "An IPsec Security Association was deleted",
    5050: "An attempt to programmatically disable the Windows Firewall was rejected",
    5051: "A file was virtualized",
    # Cryptography
    5056: "A cryptographic self test was performed",
    5057: "A cryptographic primitive operation failed",
    5058: "Key file operation",
    5059: "Key migration operation",
    5060: "Verification operation failed",
    5061: "Cryptographic operation",
    5062: "A kernel-mode cryptographic self test was performed",
    5063: "A cryptographic provider operation was attempted",
    5064: "A cryptographic context operation was attempted",
    5065: "A cryptographic context modification was attempted",
    5066: "A cryptographic function operation was attempted",
    5067: "A cryptographic function modification was attempted",
    5068: "A cryptographic function provider operation was attempted",
    5069: "A cryptographic function property operation was attempted",
    5070: "A cryptographic function property modification was attempted",
    5071: "Key access denied by Microsoft key distribution service",
    # OCSP
    5120: "OCSP Responder Service started",
    5121: "OCSP Responder Service stopped",
    5122: "A configuration entry changed in the OCSP Responder Service",
    5123: "A configuration entry changed in the OCSP Responder Service",
    5124: "A security setting was updated on the OCSP Responder Service",
    5125: "A request was submitted to the OCSP Responder Service",
    5126: "Signing certificate was automatically updated by the OCSP Responder Service",
    5127: "The OCSP Revocation Provider successfully updated the revocation information",
    # Directory service / file share
    5136: "A directory service object was modified",
    5137: "A directory service object was created",
    5138: "A directory service object was undeleted",
    5139: "A directory service object was moved",
    5140: "A network share object was accessed",
    5141: "A directory service object was deleted",
    5142: "A network share object was added",
    5143: "A network share object was modified",
    5144: "A network share object was deleted",
    5145: "A network share object was checked to see whether the client can be granted desired access",
    # Windows Filtering Platform
    5146: "The Windows Filtering Platform has blocked a packet",
    5147: "A more restrictive Windows Filtering Platform filter has blocked a packet",
    5148: "The Windows Filtering Platform detected a DoS attack and entered defensive mode",
    5149: "The DoS attack has subsided and normal processing is being resumed",
    5150: "The Windows Filtering Platform has blocked a packet",
    5151: "A more restrictive Windows Filtering Platform filter has blocked a packet",
    5152: "The Windows Filtering Platform blocked a packet",
    5153: "A more restrictive Windows Filtering Platform filter has blocked a packet",
    5154: "The Windows Filtering Platform permitted an application or service to listen on a port",
    5155: "The Windows Filtering Platform blocked an application or service from listening on a port",
    5156: "The Windows Filtering Platform has allowed a connection",
    5157: "The Windows Filtering Platform has blocked a connection",
    5158: "The Windows Filtering Platform has permitted a bind to a local port",
    5159: "The Windows Filtering Platform has blocked a bind to a local port",
    5168: "SPN check for SMB/SMB2 failed",
    5169: "A directory service object was modified",
    5170: "A directory service object was modified during a background cleanup task",
    # Credential Manager / Vault
    5376: "Credential Manager credentials were backed up",
    5377: "Credential Manager credentials were restored from a backup",
    5378: "The requested credentials delegation was disallowed by policy",
    5379: "Credential Manager credentials were read",
    5380: "Vault Find Credential",
    5381: "Vault credentials were read",
    5382: "Vault credentials were read",
    # WFP Base Filtering Engine
    5440: "A callout was present when the WFP Base Filtering Engine started",
    5441: "A filter was present when the WFP Base Filtering Engine started",
    5442: "A provider was present when the WFP Base Filtering Engine started",
    5443: "A provider context was present when the WFP Base Filtering Engine started",
    5444: "A sub-layer was present when the WFP Base Filtering Engine started",
    5446: "A Windows Filtering Platform callout has been changed",
    5447: "A Windows Filtering Platform filter has been changed",
    5448: "A Windows Filtering Platform provider has been changed",
    5449: "A Windows Filtering Platform provider context has been changed",
    5450: "A Windows Filtering Platform sub-layer has been changed",
    5451: "An IPsec Quick Mode security association was established",
    5452: "An IPsec Quick Mode security association ended",
    5453: "An IPsec negotiation failed because the IKEEXT service is not started",
    5456: "PAStore Engine applied Active Directory storage IPsec policy on the computer",
    5457: "PAStore Engine failed to apply Active Directory storage IPsec policy on the computer",
    5458: "PAStore Engine applied locally cached copy of Active Directory IPsec policy",
    5459: "PAStore Engine failed to apply locally cached copy of Active Directory IPsec policy",
    5460: "PAStore Engine applied local registry storage IPsec policy on the computer",
    5461: "PAStore Engine failed to apply local registry storage IPsec policy on the computer",
    5462: "PAStore Engine failed to apply some rules of the active IPsec policy",
    5463: "PAStore Engine polled for IPsec policy changes and detected no changes",
    5464: "PAStore Engine polled for IPsec policy changes, detected changes, and applied them",
    5465: "PAStore Engine received a control for forced reloading of IPsec policy and processed it",
    5466: "PAStore Engine could not reach Active Directory; using cached IPsec policy",
    5467: "PAStore Engine reached Active Directory and found no IPsec policy changes",
    5468: "PAStore Engine reached Active Directory, found IPsec policy changes, and applied them",
    5471: "PAStore Engine loaded local storage IPsec policy on the computer",
    5472: "PAStore Engine failed to load local storage IPsec policy on the computer",
    5473: "PAStore Engine loaded directory storage IPsec policy on the computer",
    5474: "PAStore Engine failed to load directory storage IPsec policy on the computer",
    5477: "PAStore Engine failed to add quick mode filter",
    5478: "IPsec Services has started successfully",
    5479: "IPsec Services has been shut down successfully",
    5480: "IPsec Services failed to get the complete list of network interfaces on the computer",
    5483: "IPsec Services failed to initialize RPC server and could not be started",
    5484: "IPsec Services has experienced a critical failure and has been shut down",
    5485: "IPsec Services failed to process some IPsec filters on a plug-and-play event",
    # Network / RPC / COM+
    5632: "A request was made to authenticate to a wireless network",
    5633: "A request was made to authenticate to a wired network",
    5712: "A Remote Procedure Call (RPC) was attempted",
    5888: "An object in the COM+ Catalog was modified",
    5889: "An object was deleted from the COM+ Catalog",
    5890: "An object was added to the COM+ Catalog",
    # Group Policy
    6144: "Security policy in the group policy objects has been applied successfully",
    6145: "One or more errors occurred while processing security policy in the group policy objects",
    # Network Policy Server
    6272: "Network Policy Server granted access to a user",
    6273: "Network Policy Server denied access to a user",
    6274: "Network Policy Server discarded the request for a user",
    6275: "Network Policy Server discarded the accounting request for a user",
    6276: "Network Policy Server quarantined a user",
    6277: "Network Policy Server granted access but put the user on probation (health policy)",
    6278: "Network Policy Server granted full access because the host met the health policy",
    6279: "Network Policy Server locked the user account due to repeated failed authentication",
    6280: "Network Policy Server unlocked the user account",
    6281: "Code Integrity determined that the page hashes of an image file are not valid",
    # BranchCache / firewall registration / code integrity
    6400: "BranchCache: Received an incorrectly formatted response while discovering content",
    6401: "BranchCache: Received invalid data from a peer; data discarded",
    6402: "BranchCache: The message to the hosted cache offering it data is incorrectly formatted",
    6403: "BranchCache: The hosted cache sent an incorrectly formatted response",
    6404: "BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate",
    6405: "BranchCache: Multiple instances of an event occurred",
    6406: "A product registered with Windows Firewall to control filtering",
    6407: "Windows Firewall registration event",
    6408: "A registered product failed and Windows Firewall is now controlling the filtering",
    6409: "BranchCache: A service connection point object could not be parsed",
    6410: "Code integrity determined that a file does not meet the security requirements to load",
    # Plug and Play / FIPS
    6416: "A new external device was recognized by the system",
    6417: "The FIPS mode crypto self-tests succeeded",
    6418: "The FIPS mode crypto self-tests failed",
    6419: "A request was made to disable a device",
    6420: "A device was disabled",
    6421: "A request was made to enable a device",
    6422: "A device was enabled",
    6423: "The installation of this device is forbidden by system policy",
    6424: "The installation of this device was allowed after previously being forbidden by policy",
}

# ---- Other common logs, keyed by provider name (lowercase match on a keyword)
OTHER_EVENTS = {
    "eventlog": {   # System log, provider "EventLog" / "Microsoft-Windows-Eventlog"
        104: "An event log was cleared",
        6005: "The Event Log service was started (system boot)",
        6006: "The Event Log service was stopped (clean shutdown)",
        6008: "The previous system shutdown was unexpected",
        6009: "Operating system version information recorded at boot",
        6013: "System uptime",
    },
    "service control manager": {
        7000: "A service failed to start",
        7001: "A service depends on another service that failed to start",
        7009: "A timeout was reached while waiting for a service to connect",
        7011: "A timeout was reached waiting for a transaction response from a service",
        7022: "A service hung on starting",
        7023: "A service terminated with an error",
        7024: "A service terminated with a service-specific error",
        7026: "A boot-start or system-start driver failed to load",
        7031: "A service terminated unexpectedly; corrective action will be taken",
        7032: "The Service Control Manager tried to take a corrective action after a service failure",
        7034: "A service terminated unexpectedly",
        7035: "A start/stop control was sent to a service",
        7036: "A service entered the running/stopped state",
        7040: "The start type of a service was changed",
        7045: "A new service was installed in the system",
    },
    "kernel-general": {
        1: "The system time was changed",
        12: "The operating system started",
        13: "The operating system is shutting down",
    },
    "kernel-power": {
        41: "The system rebooted without cleanly shutting down first (crash / power loss)",
        42: "The system is entering sleep",
        107: "The system resumed from sleep",
        109: "The kernel power manager initiated a shutdown transition",
    },
    "user32": {
        1074: "A process initiated a restart or shutdown",
    },
    "winlogon": {
        7001: "User logon notification (Customer Experience Improvement Program)",
        7002: "User logoff notification (Customer Experience Improvement Program)",
    },
    "localsessionmanager": {
        21: "Remote Desktop: session logon succeeded",
        22: "Remote Desktop: shell start notification received",
        23: "Remote Desktop: session logoff succeeded",
        24: "Remote Desktop: session has been disconnected",
        25: "Remote Desktop: session reconnection succeeded",
        39: "Remote Desktop: session disconnected by another session",
        40: "Remote Desktop: session disconnected (reason code recorded)",
    },
    "remoteconnectionmanager": {
        261: "Remote Desktop listener received a connection",
        1149: "Remote Desktop: user authentication succeeded (network connection)",
    },
    "application error": {1000: "Application crash (faulting application)"},
    "application hang": {1002: "Application hang"},
    "windows error reporting": {1001: "Windows Error Reporting fault bucket"},
    "windows defender": {
        1006: "Defender detected malware or other potentially unwanted software",
        1007: "Defender took action to protect the system from malware",
        1008: "Defender failed to take action on malware",
        1116: "Defender detected malware or other potentially unwanted software",
        1117: "Defender took action to protect the system from malware",
        1118: "Defender attempted to take action on malware but it failed (non-critical)",
        1119: "Defender encountered a critical error taking action on malware",
        5001: "Defender real-time protection was disabled",
        5004: "Defender real-time protection configuration changed",
        5007: "Defender configuration changed",
        5010: "Defender scanning for malware is disabled",
        5012: "Defender virus scanning is disabled",
    },
    "powershell": {   # Microsoft-Windows-PowerShell and classic "PowerShell"
        400: "PowerShell engine state changed to Available (session started)",
        403: "PowerShell engine state changed to Stopped (session ended)",
        600: "PowerShell provider started",
        800: "PowerShell pipeline execution details",
        4103: "PowerShell module logging (pipeline execution)",
        4104: "PowerShell script block logging (script executed)",
        4105: "PowerShell script block invocation started",
        4106: "PowerShell script block invocation completed",
    },
    "taskscheduler": {
        100: "Scheduled task started",
        102: "Scheduled task completed",
        106: "Scheduled task registered",
        140: "Scheduled task updated",
        141: "Scheduled task deleted",
        200: "Scheduled task action started",
        201: "Scheduled task action completed",
    },
    "sysmon": {
        1: "Sysmon: Process creation",
        2: "Sysmon: A process changed a file creation time",
        3: "Sysmon: Network connection",
        4: "Sysmon: Sysmon service state changed",
        5: "Sysmon: Process terminated",
        6: "Sysmon: Driver loaded",
        7: "Sysmon: Image loaded",
        8: "Sysmon: CreateRemoteThread",
        9: "Sysmon: RawAccessRead",
        10: "Sysmon: ProcessAccess",
        11: "Sysmon: FileCreate",
        12: "Sysmon: Registry object created or deleted",
        13: "Sysmon: Registry value set",
        14: "Sysmon: Registry key or value renamed",
        15: "Sysmon: FileCreateStreamHash",
        16: "Sysmon: Sysmon configuration change",
        17: "Sysmon: Named pipe created",
        18: "Sysmon: Named pipe connected",
        19: "Sysmon: WMI event filter activity",
        20: "Sysmon: WMI event consumer activity",
        21: "Sysmon: WMI event consumer-to-filter binding",
        22: "Sysmon: DNS query",
        23: "Sysmon: File delete (archived)",
        24: "Sysmon: Clipboard change",
        25: "Sysmon: Process tampering",
        26: "Sysmon: File delete logged",
        27: "Sysmon: File block executable",
        28: "Sysmon: File block shredding",
        29: "Sysmon: File executable detected",
        255: "Sysmon: Error",
    },
}

LOGON_TYPES = {
    "0": ("System", "Used only by the System account, typically at startup"),
    "2": ("Interactive", "Logon at the keyboard and screen of the computer"),
    "3": ("Network", "Access from the network (e.g. shared folder, mapped drive, most DC authentications)"),
    "4": ("Batch", "Scheduled task / batch job running without user interaction"),
    "5": ("Service", "A service was started by the Service Control Manager"),
    "7": ("Unlock", "The workstation was unlocked"),
    "8": ("NetworkCleartext", "Network logon with the password sent in clear text (e.g. IIS basic auth)"),
    "9": ("NewCredentials", "Caller cloned its token with new credentials for outbound connections (RunAs /netonly)"),
    "10": ("RemoteInteractive", "Remote Desktop / Terminal Services / Remote Assistance"),
    "11": ("CachedInteractive", "Interactive logon using cached domain credentials (DC not contacted)"),
    "12": ("CachedRemoteInteractive", "Remote Desktop logon using cached credentials"),
    "13": ("CachedUnlock", "Workstation unlock using cached credentials"),
}

# NTSTATUS codes used in 4625 Status/SubStatus, 4776 Status, 4624/4625 related events
NTSTATUS = {
    0x00000000: "Success",
    0xC0000022: "Access denied",
    0xC000005E: "No logon servers are currently available",
    0xC0000064: "User name does not exist",
    0xC000006A: "User name is correct but the password is wrong",
    0xC000006C: "Password does not meet policy requirements",
    0xC000006D: "Bad user name or authentication information",
    0xC000006E: "Unknown user name or bad password / account restriction",
    0xC000006F: "User tried to log on outside allowed hours",
    0xC0000070: "Workstation restriction: logon from an unauthorized workstation",
    0xC0000071: "Password has expired",
    0xC0000072: "Account is currently disabled",
    0xC000009A: "Insufficient system resources",
    0xC00000DC: "The SAM server was in the wrong state to perform the operation",
    0xC0000133: "Clock of the workstation and the domain controller are too far out of sync",
    0xC000015B: "User has not been granted the requested logon type (logon right) at this machine",
    0xC000018C: "Trust relationship between the primary domain and the trusted domain failed",
    0xC0000192: "The NetLogon service was not started",
    0xC0000193: "Account has expired",
    0xC0000224: "User is required to change password at next logon",
    0xC0000225: "Evidently a bug in Windows and not a risk",
    0xC0000234: "Account is currently locked out",
    0xC00002EE: "An error occurred during logon",
    0xC0000371: "The local account store does not contain secret material for the account",
    0xC0000413: "Authentication firewall: the machine is not allowed to authenticate to this computer",
}

# Kerberos result/failure codes (4768, 4769, 4770, 4771, 4772, 4773)
KERBEROS_CODES = {
    0x0: "KDC_ERR_NONE - Success",
    0x1: "KDC_ERR_NAME_EXP - Client's entry in database has expired",
    0x2: "KDC_ERR_SERVICE_EXP - Server's entry in database has expired",
    0x3: "KDC_ERR_BAD_PVNO - Requested protocol version not supported",
    0x4: "KDC_ERR_C_OLD_MAST_KVNO - Client's key encrypted in old master key",
    0x5: "KDC_ERR_S_OLD_MAST_KVNO - Server's key encrypted in old master key",
    0x6: "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client (user name) not found in Kerberos database",
    0x7: "KDC_ERR_S_PRINCIPAL_UNKNOWN - Server not found in Kerberos database",
    0x8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE - Multiple principal entries in database",
    0x9: "KDC_ERR_NULL_KEY - The client or server has a null key",
    0xA: "KDC_ERR_CANNOT_POSTDATE - Ticket not eligible for postdating",
    0xB: "KDC_ERR_NEVER_VALID - Requested start time is later than end time",
    0xC: "KDC_ERR_POLICY - KDC policy rejects the request (e.g. logon hours or workstation restrictions)",
    0xD: "KDC_ERR_BADOPTION - KDC cannot accommodate requested option",
    0xE: "KDC_ERR_ETYPE_NOTSUPP - KDC has no support for the encryption type",
    0xF: "KDC_ERR_SUMTYPE_NOSUPP - KDC has no support for the checksum type",
    0x10: "KDC_ERR_PADATA_TYPE_NOSUPP - KDC has no support for the pre-auth type (often smart card)",
    0x11: "KDC_ERR_TRTYPE_NO_SUPP - KDC has no support for the transited type",
    0x12: "KDC_ERR_CLIENT_REVOKED - Client credentials revoked (account disabled, expired, locked out, or logon hours)",
    0x13: "KDC_ERR_SERVICE_REVOKED - Credentials for server have been revoked",
    0x14: "KDC_ERR_TGT_REVOKED - TGT has been revoked",
    0x15: "KDC_ERR_CLIENT_NOTYET - Client not yet valid; try again later",
    0x16: "KDC_ERR_SERVICE_NOTYET - Server not yet valid; try again later",
    0x17: "KDC_ERR_KEY_EXPIRED - Password has expired",
    0x18: "KDC_ERR_PREAUTH_FAILED - Pre-authentication failed (usually a bad password)",
    0x19: "KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required",
    0x1A: "KDC_ERR_SERVER_NOMATCH - Requested server and ticket don't match",
    0x1B: "KDC_ERR_MUST_USE_USER2USER - Server principal valid for user-to-user only",
    0x1F: "KRB_AP_ERR_BAD_INTEGRITY - Integrity check on decrypted field failed",
    0x20: "KRB_AP_ERR_TKT_EXPIRED - Ticket has expired",
    0x21: "KRB_AP_ERR_TKT_NYV - Ticket not yet valid",
    0x22: "KRB_AP_ERR_REPEAT - Request is a replay",
    0x23: "KRB_AP_ERR_NOT_US - The ticket isn't for us",
    0x24: "KRB_AP_ERR_BADMATCH - Ticket and authenticator don't match",
    0x25: "KRB_AP_ERR_SKEW - Clock skew too great",
    0x26: "KRB_AP_ERR_BADADDR - Incorrect network address",
    0x27: "KRB_AP_ERR_BADVERSION - Protocol version mismatch",
    0x28: "KRB_AP_ERR_MSG_TYPE - Invalid message type",
    0x29: "KRB_AP_ERR_MODIFIED - Message stream modified",
    0x2A: "KRB_AP_ERR_BADORDER - Message out of order",
    0x2C: "KRB_AP_ERR_BADKEYVER - Specified version of key is not available",
    0x2D: "KRB_AP_ERR_NOKEY - Service key not available",
    0x2E: "KRB_AP_ERR_MUT_FAIL - Mutual authentication failed",
    0x2F: "KRB_AP_ERR_BADDIRECTION - Incorrect message direction",
    0x30: "KRB_AP_ERR_METHOD - Alternative authentication method required",
    0x31: "KRB_AP_ERR_BADSEQ - Incorrect sequence number in message",
    0x32: "KRB_AP_ERR_INAPP_CKSUM - Inappropriate type of checksum in message",
    0x33: "KRB_AP_PATH_NOT_ACCEPTED - Desired path is unreachable",
    0x34: "KRB_ERR_RESPONSE_TOO_BIG - Too much data",
    0x3C: "KRB_ERR_GENERIC - Generic error",
    0x3D: "KRB_ERR_FIELD_TOOLONG - Field is too long for this implementation",
    0x3E: "KDC_ERR_CLIENT_NOT_TRUSTED - Client not trusted (smart card / PKINIT)",
    0x3F: "KDC_ERR_KDC_NOT_TRUSTED - KDC not trusted (smart card / PKINIT)",
    0x40: "KDC_ERR_INVALID_SIG - Signature is invalid",
    0x41: "KDC_ERR_KEY_TOO_WEAK - Key too weak",
    0x42: "KRB_AP_ERR_USER_TO_USER_REQUIRED - User-to-user authorization required",
    0x43: "KRB_AP_ERR_NO_TGT - No TGT was presented or available",
    0x44: "KDC_ERR_WRONG_REALM - Incorrect domain or principal",
}
KERBEROS_EVENTS = {4768, 4769, 4770, 4771, 4772, 4773}

TICKET_ENCRYPTION = {
    0x1: "DES-CBC-CRC (weak)",
    0x3: "DES-CBC-MD5 (weak)",
    0x11: "AES128-CTS-HMAC-SHA1-96",
    0x12: "AES256-CTS-HMAC-SHA1-96",
    0x17: "RC4-HMAC (weak)",
    0x18: "RC4-HMAC-EXP (weak)",
    0xFFFFFFFF: "Failure event (no ticket issued)",
}

PREAUTH_TYPES = {
    "0": "No pre-authentication (possible AS-REP roasting exposure)",
    "2": "PA-ENC-TIMESTAMP (standard password)",
    "11": "PA-ETYPE-INFO",
    "15": "PA-PK-AS-REP_OLD (smart card)",
    "16": "PA-PK-AS-REQ (smart card)",
    "17": "PA-PK-AS-REP (smart card)",
    "19": "PA-ETYPE-INFO2",
    "20": "PA-SVR-REFERRAL-INFO",
    "138": "PA-ENCRYPTED-CHALLENGE (Kerberos armoring / FAST)",
}

# %%NNNN message-table insertion strings that appear in EventData values
MESSAGE_CODES = {
    "%%1537": "DELETE", "%%1538": "READ_CONTROL", "%%1539": "WRITE_DAC",
    "%%1540": "WRITE_OWNER", "%%1541": "SYNCHRONIZE", "%%1542": "ACCESS_SYS_SEC",
    "%%1793": "<value not set>", "%%1794": "<never>",
    "%%1832": "Identification", "%%1833": "Impersonation", "%%1840": "Delegation",
    "%%1842": "Yes", "%%1843": "No",
    "%%1936": "Type 1 - Full token, UAC disabled or built-in admin",
    "%%1937": "Type 2 - Elevated token (Run as administrator)",
    "%%1938": "Type 3 - Limited token (normal UAC-filtered)",
    "%%2048": "Account Enabled",
    "%%2080": "Account Disabled",
    "%%2081": "'Home Directory Required' - Enabled",
    "%%2082": "'Password Not Required' - Enabled",
    "%%2083": "'Temp Duplicate Account' - Enabled",
    "%%2084": "'Normal Account' - Enabled",
    "%%2085": "'MNS Logon Account' - Enabled",
    "%%2086": "'Interdomain Trust Account' - Enabled",
    "%%2087": "'Workstation Trust Account' - Enabled",
    "%%2088": "'Server Trust Account' - Enabled",
    "%%2089": "'Don't Expire Password' - Enabled",
    "%%2090": "Account Unlocked",
    "%%2091": "'Encrypted Text Password Allowed' - Enabled",
    "%%2092": "'Smartcard Required' - Enabled",
    "%%2093": "'Trusted For Delegation' - Enabled",
    "%%2094": "'Not Delegated' - Enabled",
    "%%2095": "'Use DES Key Only' - Enabled",
    "%%2096": "'Don't Require Preauth' - Enabled",
    "%%2097": "'Password Expired' - Enabled",
    "%%2098": "'Trusted To Authenticate For Delegation' - Enabled",
    "%%2304": "An error occurred during logon",
    "%%2305": "The specified user account has expired",
    "%%2306": "The NetLogon component is not active",
    "%%2307": "Account locked out",
    "%%2308": "The user has not been granted the requested logon type at this machine",
    "%%2309": "The specified account's password has expired",
    "%%2310": "Account currently disabled",
    "%%2311": "Account logon time restriction violation",
    "%%2312": "User not allowed to logon at this computer",
    "%%2313": "Unknown user name or bad password",
    "%%4416": "ReadData (or ListDirectory)", "%%4417": "WriteData (or AddFile)",
    "%%4418": "AppendData (or AddSubdirectory)", "%%4419": "ReadEA", "%%4420": "WriteEA",
    "%%4421": "Execute/Traverse", "%%4422": "DeleteChild", "%%4423": "ReadAttributes",
    "%%4424": "WriteAttributes",
    "%%14592": "Inbound", "%%14593": "Outbound",
}

WELL_KNOWN_SIDS = {
    "S-1-0-0": "NULL SID", "S-1-1-0": "Everyone", "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-18": "SYSTEM", "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators", "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
}
WELL_KNOWN_RIDS = {   # last part of a domain SID
    "500": "built-in Administrator", "501": "built-in Guest", "502": "krbtgt",
    "512": "Domain Admins", "513": "Domain Users", "514": "Domain Guests",
    "515": "Domain Computers", "516": "Domain Controllers", "518": "Schema Admins",
    "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
}
WELL_KNOWN_LOGON_IDS = {0x3E7: "SYSTEM", 0x3E4: "NETWORK SERVICE", 0x3E5: "LOCAL SERVICE"}

# Keyword bits that mark Security events as success or failure
KEYWORD_AUDIT_SUCCESS = 0x0020000000000000
KEYWORD_AUDIT_FAILURE = 0x0010000000000000
LEVELS = {"0": "Information", "1": "Critical", "2": "Error", "3": "Warning",
          "4": "Information", "5": "Verbose"}


# ============================================================================
#  DECODING HELPERS
# ============================================================================

def to_int(value):
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except (ValueError, AttributeError):
        return None


def describe_event(event_id, provider=""):
    eid = to_int(event_id)
    if eid is None:
        return "Unknown"
    p = provider.lower()
    if eid in SECURITY_EVENTS and (not p or "security-auditing" in p or p == "microsoft-windows-eventlog"):
        return SECURITY_EVENTS[eid]
    for key, table in OTHER_EVENTS.items():
        if key in p and eid in table:
            return table[eid]
    return f"Not in reference table ({provider or 'unknown provider'})"


def decode_status(value, event_id):
    """Turn a hex status/failure code into plain English."""
    if not value or value == "-":
        return ""
    code = to_int(value)
    if code is None:
        return value
    if to_int(event_id) in KERBEROS_EVENTS:
        meaning = KERBEROS_CODES.get(code)
    else:
        meaning = NTSTATUS.get(code & 0xFFFFFFFF)
    return f"{value} - {meaning}" if meaning else f"{value} - (unrecognized code)"


def decode_logon_type(value):
    if value in LOGON_TYPES:
        name, meaning = LOGON_TYPES[value]
        return f"{value} - {name}", meaning
    return (value, "") if value else ("", "")


def decode_sid(sid):
    if not sid or sid == "-":
        return ""
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    rid = sid.rsplit("-", 1)[-1]
    if sid.startswith("S-1-5-21-") and rid in WELL_KNOWN_RIDS:
        return WELL_KNOWN_RIDS[rid]
    return ""


def decode_value(name, value, event_id):
    """Decode any single EventData field value."""
    if not value:
        return value
    # Replace %%codes (can be several, separated by whitespace)
    if "%%" in value:
        value = re.sub(r"%%\d+", lambda m: MESSAGE_CODES.get(m.group(0), m.group(0)), value)
        value = re.sub(r"\s+", " ", value).strip()
    n = name.lower()
    if n in ("status", "substatus", "failurecode", "result"):
        return decode_status(value, event_id)
    if n == "logontype":
        return decode_logon_type(value)[0]
    if n == "ticketencryptiontype":
        code = to_int(value)
        return f"{value} - {TICKET_ENCRYPTION.get(code, 'unrecognized')}" if code is not None else value
    if n == "preauthtype":
        return f"{value} - {PREAUTH_TYPES[value]}" if value in PREAUTH_TYPES else value
    if n.endswith("sid"):
        known = decode_sid(value)
        return f"{value} ({known})" if known else value
    if n.endswith("logonid"):
        code = to_int(value)
        if code in WELL_KNOWN_LOGON_IDS:
            return f"{value} ({WELL_KNOWN_LOGON_IDS[code]})"
    return value


def lookup(code):
    """--lookup helper: print everything we know about an ID or code."""
    found = False
    n = to_int(code)
    if n is not None:
        if n in SECURITY_EVENTS:
            print(f"Security event {n}: {SECURITY_EVENTS[n]}"); found = True
        for prov, table in OTHER_EVENTS.items():
            if n in table:
                print(f"{prov} event {n}: {table[n]}"); found = True
        if str(n) in LOGON_TYPES:
            name, meaning = LOGON_TYPES[str(n)]
            print(f"Logon type {n}: {name} - {meaning}"); found = True
        if (n & 0xFFFFFFFF) in NTSTATUS and code.lower().startswith("0xc"):
            print(f"NTSTATUS {code}: {NTSTATUS[n & 0xFFFFFFFF]}"); found = True
        if code.lower().startswith("0x") and n in KERBEROS_CODES:
            print(f"Kerberos code {code}: {KERBEROS_CODES[n]}"); found = True
    if code in MESSAGE_CODES:
        print(f"{code}: {MESSAGE_CODES[code]}"); found = True
    if not found:
        print(f"No reference entry for {code}")


# ============================================================================
#  FILE HANDLING AND PARSING
# ============================================================================

def pick_file_with_dialog():
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        return None
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    chosen = filedialog.askopenfilename(
        title="Choose an event log XML file",
        filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
    root.destroy()
    return chosen or None


def resolve_inputs(path_str):
    path = Path(path_str.strip().strip('"')).expanduser()
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix.lower() == ".xml")
        if not files:
            sys.exit(f"No .xml files found in folder: {path}")
        return files
    if path.is_file():
        return [path]
    sys.exit(f"Path not found: {path}")


def local(tag):
    return tag.rsplit("}", 1)[-1]


def stream_events(path, chunk_size=1024 * 1024):
    """Yield <Event> elements one at a time; works with or without a root element."""
    parser = ET.XMLPullParser(events=("end",))
    parser.feed("<Wrapper>")
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        first = True
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            if first:
                chunk = re.sub(r"^\s*<\?xml[^>]*\?>", "", chunk)
                first = False
            parser.feed(chunk)
            for _, elem in parser.read_events():
                if local(elem.tag) == "Event":
                    yield elem
                    elem.clear()
    parser.feed("</Wrapper>")
    for _, elem in parser.read_events():
        if local(elem.tag) == "Event":
            yield elem


def parse_time(raw):
    """Return a naive UTC datetime (Excel can't store time zones), or None."""
    m = re.match(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?", raw or "")
    if not m:
        return None
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return None


def format_time(raw):
    dt = parse_time(raw)
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else (raw or "")


def first(data, *names):
    for n in names:
        v = data.get(n, "")
        if v and v != "-":
            return v
    return ""


COLUMNS = [
    "Time (UTC)", "Record", "Channel", "Provider", "Event ID", "Description", "Result",
    "Level", "Computer", "Subject Account", "Target Account", "Account Type",
    "Logon Type", "Logon Type Meaning", "Source IP", "Source Port", "Workstation",
    "Process", "Auth Package", "Status", "Sub Status", "Failure Reason",
    "Logon ID", "Other Details",
]

# Fields already shown in dedicated columns (left out of "Other Details")
SHOWN_FIELDS = {
    "SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName",
    "LogonType", "IpAddress", "IpPort", "WorkstationName", "Workstation",
    "ProcessName", "NewProcessName", "AuthenticationPackageName", "PackageName",
    "Status", "SubStatus", "FailureCode", "FailureReason", "TargetLogonId",
}


def event_to_row(ev):
    system, data = {}, {}
    time_raw = provider = ""
    for child in ev:
        name = local(child.tag)
        if name == "System":
            for s in child:
                sname = local(s.tag)
                if sname == "TimeCreated":
                    time_raw = s.get("SystemTime", "")
                elif sname == "Provider":
                    provider = s.get("Name", "")
                elif s.text:
                    system[sname] = s.text.strip()
        elif name in ("EventData", "UserData"):
            unnamed = 0
            for d in child.iter():
                if d is child:
                    continue
                tag = local(d.tag)
                if tag == "Data":
                    key = d.get("Name")
                    if not key:
                        unnamed += 1
                        key = f"Data{unnamed}"
                    data[key] = (d.text or "").strip()
                elif len(d) == 0 and d.text and d.text.strip():
                    data[tag] = d.text.strip()   # UserData uses named child elements

    event_id = system.get("EventID", "")
    eid = to_int(event_id)

    # Success / failure from keywords
    kw = to_int(system.get("Keywords", "0")) or 0
    if kw & KEYWORD_AUDIT_FAILURE:
        result = "Audit Failure"
    elif kw & KEYWORD_AUDIT_SUCCESS:
        result = "Audit Success"
    else:
        result = ""

    def account(user_key, domain_key):
        u, d = data.get(user_key, ""), data.get(domain_key, "")
        if not u or u == "-":
            return ""
        return f"{d}\\{u}" if d and d != "-" else u

    subject = account("SubjectUserName", "SubjectDomainName")
    target = account("TargetUserName", "TargetDomainName")
    main_acct = data.get("TargetUserName") or data.get("SubjectUserName", "")
    if main_acct.endswith("$"):
        acct_type = "Computer"
    elif main_acct.upper() in ("ANONYMOUS LOGON", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        acct_type = "Built-in"
    elif main_acct and main_acct != "-":
        acct_type = "User"
    else:
        acct_type = ""

    lt_label, lt_meaning = decode_logon_type(data.get("LogonType", ""))

    status_raw = first(data, "Status", "FailureCode")
    failure = data.get("FailureReason", "")
    failure = decode_value("FailureReason", failure, event_id) if failure else ""

    other = []
    for k, v in data.items():
        if k in SHOWN_FIELDS or not v or v == "-":
            continue
        other.append(f"{k}={decode_value(k, v, event_id)}")

    return {
        "_sort": time_raw,
        "Time (UTC)": format_time(time_raw),
        "_dt": parse_time(time_raw),
        "_data": data,
        "Record": system.get("EventRecordID", ""),
        "Channel": system.get("Channel", ""),
        "Provider": provider,
        "Event ID": str(eid) if eid is not None else event_id,
        "Description": describe_event(event_id, provider),
        "Result": result,
        "Level": LEVELS.get(system.get("Level", ""), system.get("Level", "")),
        "Computer": system.get("Computer", ""),
        "Subject Account": subject,
        "Target Account": target,
        "Target User Name": "" if data.get("TargetUserName", "") == "-" else data.get("TargetUserName", ""),
        "Account Type": acct_type,
        "Logon Type": lt_label,
        "Logon Type Meaning": lt_meaning,
        "Source IP": first(data, "IpAddress", "SourceAddress", "ClientAddress"),
        "Source Port": first(data, "IpPort", "SourcePort"),
        "Workstation": first(data, "WorkstationName", "Workstation"),
        "Process": first(data, "ProcessName", "NewProcessName", "Application"),
        "Auth Package": first(data, "AuthenticationPackageName", "PackageName"),
        "Status": decode_status(status_raw, event_id),
        "Sub Status": decode_status(data.get("SubStatus", ""), event_id),
        "Failure Reason": failure,
        "Logon ID": decode_value("TargetLogonId", data.get("TargetLogonId", ""), event_id),
        "Other Details": "; ".join(other),
    }


def parse_file(path):
    rows = []
    start = time.time()
    try:
        for i, ev in enumerate(stream_events(path), 1):
            rows.append(event_to_row(ev))
            if i % 10000 == 0:
                print(f"  ...{i:,} events read", end="\r", flush=True)
    except ET.ParseError as err:
        print(f"\n  Warning: XML error in {path.name} ({err}). "
              f"Keeping the {len(rows):,} events read before it.")
    print(f"  Read {len(rows):,} events from {path.name} in {time.time() - start:.1f}s   ")
    return rows


# ============================================================================
#  SUMMARY DATA
# ============================================================================

FAILED_LOGON_IDS = ("4625", "4771", "4776")

REPORT_COLUMNS = [
    "Time (UTC)", "Event ID", "Description", "Result", "Flags", "Computer", "Primary Account",
    "Target User Name", "Account Type", "Logon Type", "Source IP", "Workstation", "Status", "Sub Status",
    "Failure Reason", "Subject Account", "Target Account", "Logon Type Meaning",
    "Source Port", "Process", "Auth Package", "Logon ID", "Level", "Channel",
    "Provider", "Record", "Other Details",
]
KEY_COLUMN_COUNT = 14          # the first 14 columns show by default


def primary_account(r):
    return r["Target Account"] or r["Subject Account"]


def is_failed_logon(r):
    return r["Result"] == "Audit Failure" and r["Event ID"] in FAILED_LOGON_IDS


def group(rows, keyfunc, limit=None):
    counts = Counter(keyfunc(r) for r in rows)
    return counts.most_common(limit)


def build_sections(rows):
    """Each section: title, column headings, and rows of (cells, count, filter)."""
    failed = [r for r in rows if is_failed_logon(r)]
    none = lambda v: v or "(none)"
    sections = []

    def add(title, headers, items, note=""):
        sections.append({"title": title, "headers": headers, "items": items, "note": note})

    add("Events by Event ID", ["Event ID", "Description"],
        [([eid, desc], n, {"Event ID": eid})
         for (eid, desc), n in group(rows, lambda r: (r["Event ID"], r["Description"]))])
    add("Events by result", ["Result"],
        [([none(res)], n, {"Result": res}) for (res,), n in group(rows, lambda r: (r["Result"],))])
    add("Events by logon type", ["Logon type", "What it means"],
        [([lt, meaning], n, {"Logon Type": lt})
         for (lt, meaning), n in group([r for r in rows if r["Logon Type"]],
                                       lambda r: (r["Logon Type"], r["Logon Type Meaning"]))])
    add("Events by account type", ["Account type"],
        [([none(t)], n, {"Account Type": t}) for (t,), n in group(rows, lambda r: (r["Account Type"],))],
        "Accounts ending in $ are computer accounts.")
    prefix = EXCLUDE_ACCOUNT_PREFIX.lower()
    other_accounts = [r for r in rows
                      if not (prefix and primary_account(r).lower().startswith(prefix))]
    add("Top 25 accounts", ["Account"],
        [([none(a)], n, {"Primary Account": a})
         for (a,), n in group(other_accounts, lambda r: (primary_account(r),), 25)],
        f'Excludes accounts starting with "{EXCLUDE_ACCOUNT_PREFIX}".' if prefix else "")
    add("Top 25 computers", ["Computer"],
        [([none(c)], n, {"Computer": c}) for (c,), n in group(rows, lambda r: (r["Computer"],), 25)])
    add("Top 25 source IP addresses", ["Source IP"],
        [([ip], n, {"Source IP": ip})
         for (ip,), n in group([r for r in rows if r["Source IP"]], lambda r: (r["Source IP"],), 25)])

    fnote = "Failed logons are Audit Failure events with ID 4625, 4771 or 4776."
    add("Failed logons by account", ["Account"],
        [([none(a)], n, {"Primary Account": a, "_failed": True})
         for (a,), n in group(failed, lambda r: (primary_account(r),), 25)], fnote)
    add("Failed logons by reason", ["Status", "Sub status"],
        [([none(st), none(sub)], n, {"Status": st, "Sub Status": sub, "_failed": True})
         for (st, sub), n in group(failed, lambda r: (r["Status"], r["Sub Status"]))], fnote)
    add("Failed logons by source IP", ["Source IP"],
        [([none(ip)], n, {"Source IP": ip, "_failed": True})
         for (ip,), n in group(failed, lambda r: (r["Source IP"],), 25)], fnote)

    unknown = [r for r in rows if r["Description"].startswith("Not in reference")]
    if unknown:
        add("Event IDs not in the reference table", ["Event ID", "Provider"],
            [([eid, prov], n, {"Event ID": eid, "Provider": prov})
             for (eid, prov), n in group(unknown, lambda r: (r["Event ID"], r["Provider"]))])
    return sections


def summary_lines(rows):
    failed = [r for r in rows if is_failed_logon(r)]
    yield "=== Summary ==="
    yield f"Total events:   {len(rows):,}"
    yield f"Time range:     {rows[0]['Time (UTC)']}  to  {rows[-1]['Time (UTC)']}"
    yield f"Audit Success:  {sum(r['Result'] == 'Audit Success' for r in rows):,}"
    yield f"Audit Failure:  {sum(r['Result'] == 'Audit Failure' for r in rows):,}"
    yield f"Failed logons:  {len(failed):,}"


# ============================================================================
#  SUSPICIOUS ACTIVITY DETECTION
# ============================================================================
# Each rule looks for a pattern a security analyst would want to review. A
# finding is a lead, not proof: always check the matching events before acting.

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
BUILTIN_NAMES = {"system", "local service", "network service", "anonymous logon", "-", ""}
LOGON_EVENTS = {"4624", "4625", "4634", "4647", "4648", "4778", "4779", "4800", "4801"}
CHURN_EVENTS = {"4624", "4634", "4647"}
PRIV_GROUP_WORDS = ("admin", "enterprise", "schema", "operators", "remote desktop",
                    "dnsadmins", "group policy creator", "key admins")


def raw(r, *names):
    for n in names:
        v = r["_data"].get(n, "")
        if v and v != "-":
            return v
    return ""


def account_name(r):
    """Bare account name used to group events (no domain, lower case)."""
    return (raw(r, "TargetUserName") or raw(r, "SubjectUserName")).lower()


def is_person(r):
    """True for real user accounts (not computers, built-ins or virtual accounts)."""
    name = account_name(r)
    return bool(name) and not name.endswith("$") and name not in BUILTIN_NAMES \
        and not name.startswith(("dwm-", "umfd-"))


def local_hour(dt):
    return (dt + timedelta(hours=UTC_OFFSET_HOURS)).hour


def in_off_hours(dt):
    h = local_hour(dt)
    if OFF_HOURS_START <= OFF_HOURS_END:
        return OFF_HOURS_START <= h < OFF_HOURS_END
    return h >= OFF_HOURS_START or h < OFF_HOURS_END      # window crosses midnight


def bursts(items, window_seconds, threshold):
    """items: time-sorted list of (datetime, row_index). Returns groups of items where
    at least `threshold` fall inside any `window_seconds` window (overlaps merged)."""
    episodes, cur, i = [], None, 0
    for j in range(len(items)):
        while (items[j][0] - items[i][0]).total_seconds() > window_seconds:
            i += 1
        if j - i + 1 >= threshold:
            if cur and i <= cur[1]:
                cur[1] = j
            else:
                if cur:
                    episodes.append(cur)
                cur = [i, j]
    if cur:
        episodes.append(cur)
    return [items[a:b + 1] for a, b in episodes]


def detect_suspicious(rows):
    findings = []

    def add(sev, rule, who, idxs, detail):
        idxs = sorted(set(idxs))
        if not idxs:
            return
        times = [rows[i]["_dt"] for i in idxs if rows[i]["_dt"]]
        findings.append({
            "severity": sev, "rule": rule, "who": who, "rows": idxs, "detail": detail,
            "first": min(times).strftime("%Y-%m-%d %H:%M:%S") if times else "",
            "last": max(times).strftime("%Y-%m-%d %H:%M:%S") if times else "",
        })

    def label(i):
        return primary_account(rows[i]) or account_name(rows[i]) or "(unknown)"

    by_eid = defaultdict(list)
    for i, r in enumerate(rows):
        by_eid[r["Event ID"]].append(i)
    timed = lambda idxs: [(rows[i]["_dt"], i) for i in idxs if rows[i]["_dt"]]

    failed = [i for i, r in enumerate(rows) if is_failed_logon(r)]

    # 1. Audit log cleared
    cleared = by_eid["1102"] + [i for i in by_eid["104"] if "eventlog" in rows[i]["Provider"].lower()]
    if cleared:
        add("High", "Audit log cleared", ", ".join(sorted({label(i) for i in cleared})), cleared,
            "Someone cleared an event log. Attackers often do this to hide what they did.")

    # 2. Brute force: many failed logons against one account in a short time
    per_acct = defaultdict(list)
    for i in failed:
        per_acct[account_name(rows[i])].append(i)
    for name, idxs in per_acct.items():
        for ep in bursts(timed(idxs), BRUTE_FORCE_WINDOW_MIN * 60, BRUTE_FORCE_THRESHOLD):
            sev = "High" if len(ep) >= BRUTE_FORCE_THRESHOLD * 4 else "Medium"
            ips = sorted({rows[i]["Source IP"] for _, i in ep if rows[i]["Source IP"]})
            add(sev, "Possible password guessing", label(ep[0][1]), [i for _, i in ep],
                f"{len(ep)} failed logons for this account within {BRUTE_FORCE_WINDOW_MIN}-minute windows"
                + (f", from {', '.join(ips[:5])}" if ips else "") + ".")

    # 3. Password spraying: one source failing against many different accounts
    per_ip = defaultdict(list)
    for i in failed:
        ip = rows[i]["Source IP"] or rows[i]["Workstation"]
        if ip and ip not in ("127.0.0.1", "::1"):
            per_ip[ip].append(i)
    for ip, idxs in per_ip.items():
        for ep in bursts(timed(idxs), SPRAY_WINDOW_MIN * 60, SPRAY_ACCOUNTS):
            names = {account_name(rows[i]) for _, i in ep}
            if len(names) >= SPRAY_ACCOUNTS:
                add("High", "Possible password spraying", ip, [i for _, i in ep],
                    f"{len(ep)} failed logons against {len(names)} different accounts from this source.")

    # 4. Successful logon right after repeated failures
    acct_events = defaultdict(list)
    for i in failed + by_eid["4624"]:
        if rows[i]["_dt"]:
            acct_events[account_name(rows[i])].append(i)
    for name, idxs in acct_events.items():
        idxs.sort(key=lambda i: rows[i]["_dt"])
        recent, hits = [], []
        for i in idxs:
            t = rows[i]["_dt"]
            recent = [f for f in recent if (t - rows[f]["_dt"]).total_seconds() <= SUCCESS_AFTER_FAIL_MIN * 60]
            if rows[i]["Event ID"] == "4624":
                if len(recent) >= SUCCESS_AFTER_FAIL_COUNT:
                    hits.extend(recent + [i])
                    recent = []
            else:
                recent.append(i)
        if hits:
            add("High", "Successful logon after repeated failures", label(hits[-1]), hits,
                f"The account logged on successfully after {SUCCESS_AFTER_FAIL_COUNT}+ failures within "
                f"{SUCCESS_AFTER_FAIL_MIN} minutes. A guessed password is one possible explanation.")

    # 5. Logons to disabled, expired or locked accounts; logons with made-up user names
    bad_state = {"0xc0000072": "disabled", "0xc0000193": "expired", "0xc0000234": "locked out",
                 "0xc000006f": "outside allowed hours", "0xc0000070": "from a restricted workstation"}
    grouped = defaultdict(list)
    unknown_users = defaultdict(list)
    for i in by_eid["4625"] + by_eid["4776"]:
        code = (raw(rows[i], "SubStatus") or raw(rows[i], "Status")).lower()
        if code in bad_state:
            grouped[(account_name(rows[i]), bad_state[code])].append(i)
        elif code == "0xc0000064":
            unknown_users[rows[i]["Source IP"] or rows[i]["Workstation"] or "(unknown source)"].append(i)
    for (name, state), idxs in grouped.items():
        add("Medium", f"Logon attempt on {state} account", label(idxs[0]), idxs,
            f"{len(idxs)} attempt(s) to use an account that is {state}.")
    for src, idxs in unknown_users.items():
        names = {account_name(rows[i]) for i in idxs}
        if len(names) >= 3:
            add("Medium", "Logons with non-existent user names", src, idxs,
                f"{len(idxs)} attempts using {len(names)} user names that don't exist, "
                "which suggests someone guessing account names.")

    # 6. Account lockouts
    locks = defaultdict(list)
    for i in by_eid["4740"]:
        locks[account_name(rows[i])].append(i)
    for name, idxs in locks.items():
        add("Medium", "Account locked out", label(idxs[0]), idxs,
            f"Locked out {len(idxs)} time(s). Check the failed logons just before each lockout.")

    # 7. Off-hours activity by people (not computers)
    off = defaultdict(list)
    for i, r in enumerate(rows):
        if r["Event ID"] in LOGON_EVENTS and r["_dt"] and is_person(r) and in_off_hours(r["_dt"]):
            off[account_name(r)].append(i)
    for name, idxs in off.items():
        interactive = [i for i in idxs if raw(rows[i], "LogonType") in ("2", "7", "10", "11")
                       or rows[i]["Event ID"] in ("4625", "4778")]
        sev = "Medium" if interactive else "Low"
        add(sev, "Activity during off-hours", label(idxs[0]), idxs,
            f"{len(idxs)} logon/logoff events between {OFF_HOURS_START:02d}:00 and {OFF_HOURS_END:02d}:00 "
            f"local time" + (f", including {len(interactive)} hands-on-keyboard, Remote Desktop or failed logons"
                             if interactive else "") + ".")

    # 8. Constant logons / logoffs (rapid churn)
    churn = defaultdict(list)
    for e in CHURN_EVENTS:
        for i in by_eid[e]:
            if is_person(rows[i]):
                churn[account_name(rows[i])].append(i)
    for name, idxs in churn.items():
        items = sorted(timed(idxs))
        for ep in bursts(items, CHURN_WINDOW_MIN * 60, CHURN_THRESHOLD):
            add("Medium", "Rapid repeated logons/logoffs", label(ep[0][1]), [i for _, i in ep],
                f"{len(ep)} logon/logoff events within {CHURN_WINDOW_MIN}-minute windows. Can indicate "
                "scripted access, a tool scanning the network, or a misconfigured service using a person's account.")

    # 9. One person logging on from many different sources within an hour
    per_hour = defaultdict(list)
    for i in by_eid["4624"]:
        r = rows[i]
        if r["_dt"] and is_person(r):
            per_hour[(account_name(r), r["_dt"].replace(minute=0, second=0, microsecond=0))].append(i)
    many = defaultdict(list)
    for (name, _), idxs in per_hour.items():
        srcs = {rows[i]["Source IP"] or rows[i]["Workstation"] for i in idxs} - {""}
        if len(srcs) >= MANY_SOURCES:
            many[name].extend(idxs)
    for name, idxs in many.items():
        srcs = sorted({rows[i]["Source IP"] or rows[i]["Workstation"] for i in idxs} - {""})
        add("Low", "Logons from many different sources", label(idxs[0]), idxs,
            f"Logged on from {len(srcs)} different addresses/workstations within an hour "
            f"({', '.join(srcs[:5])}{'...' if len(srcs) > 5 else ''}). Could be credential theft or lateral movement.")

    # 10. Changes to privileged groups
    for e, verb in (("4728", "added to"), ("4732", "added to"), ("4756", "added to"),
                    ("4729", "removed from"), ("4733", "removed from"), ("4757", "removed from")):
        for i in by_eid[e]:
            grp = raw(rows[i], "TargetUserName")
            member = raw(rows[i], "MemberName", "MemberSid")
            m = re.match(r"CN=([^,]+)", member)
            member = m.group(1) if m else member
            by = primary_account({**rows[i], "Target Account": ""}) or "(unknown)"
            privileged = any(w in grp.lower() for w in PRIV_GROUP_WORDS)
            add("High" if privileged else "Low",
                "Privileged group membership changed" if privileged else "Group membership changed",
                grp, [i], f"{member or 'A member'} was {verb} {grp} by {by}.")

    # 11. Account management
    acct_rules = {
        "4720": ("Medium", "User account created"), "4726": ("Medium", "User account deleted"),
        "4722": ("Low", "User account enabled"), "4724": ("Medium", "Password reset by another account"),
        "4781": ("Medium", "Account renamed"), "4765": ("High", "SID History added to an account"),
        "4766": ("High", "Failed attempt to add SID History"),
        "4794": ("High", "Directory Services Restore Mode password set attempt"),
        "4782": ("High", "Password hash of an account was accessed"),
    }
    for e, (sev, rule) in acct_rules.items():
        idxs = by_eid[e]
        if e == "4724":   # self-service resets are normal
            idxs = [i for i in idxs if raw(rows[i], "SubjectUserName").lower() != raw(rows[i], "TargetUserName").lower()]
        if idxs:
            targets = sorted({raw(rows[i], "TargetUserName") or "?" for i in idxs})
            add(sev, rule, ", ".join(targets[:5]) + ("..." if len(targets) > 5 else ""), idxs,
                f"{len(idxs)} event(s). Confirm each change was authorised.")

    # 12. Persistence: new services and scheduled tasks
    for e, rule, field in (("4697", "New service installed", "ServiceName"),
                           ("7045", "New service installed", "ServiceName"),
                           ("4698", "Scheduled task created", "TaskName")):
        for i in by_eid[e]:
            name = raw(rows[i], field) or "(unnamed)"
            path = raw(rows[i], "ServiceFileName", "ImagePath")
            add("Medium", rule, f"{name} on {rows[i]['Computer']}", [i],
                "Malware often installs services or tasks to survive reboots."
                + (f" Runs: {path}" if path else ""))

    # 13. Security controls weakened, malware detected
    control_rules = {
        "4719": ("Medium", "Audit policy changed"), "4906": ("Medium", "CrashOnAuditFail changed"),
        "4950": ("Low", "Windows Firewall setting changed"), "5025": ("Medium", "Windows Firewall service stopped"),
        "4946": ("Low", "Firewall rule added"), "4948": ("Low", "Firewall rule deleted"),
        "5001": ("High", "Defender real-time protection disabled"),
        "1116": ("High", "Malware detected by Defender"), "1117": ("High", "Defender acted on malware"),
        "1006": ("High", "Malware detected by Defender"), "1119": ("High", "Defender failed to act on malware"),
    }
    for e, (sev, rule) in control_rules.items():
        idxs = by_eid[e]
        if e in ("1116", "1117", "1006", "1119", "5001"):
            idxs = [i for i in idxs if "defender" in rows[i]["Provider"].lower()]
        if idxs:
            comps = sorted({rows[i]["Computer"] for i in idxs})
            add(sev, rule, ", ".join(comps[:5]), idxs, f"{len(idxs)} event(s).")

    # 14. Kerberos attack indicators
    roast = defaultdict(list)
    for i in by_eid["4769"]:
        enc = raw(rows[i], "TicketEncryptionType").lower()
        svc = raw(rows[i], "ServiceName").lower()
        if enc in ("0x17", "0x18") and not svc.endswith("$") and svc != "krbtgt":
            roast[account_name(rows[i])].append(i)
    for name, idxs in roast.items():
        svcs = {raw(rows[i], "ServiceName").lower() for i in idxs}
        if len(svcs) >= KERBEROAST_SERVICES:
            add("Medium", "Possible Kerberoasting", label(idxs[0]), idxs,
                f"Requested weak RC4 service tickets for {len(svcs)} different services. "
                "Attackers do this to crack service account passwords offline.")
    asrep = [i for i in by_eid["4768"] if raw(rows[i], "PreAuthType") == "0"]
    if asrep:
        add("Medium", "Kerberos logon without pre-authentication",
            ", ".join(sorted({label(i) for i in asrep})[:5]), asrep,
            "Accounts that don't require pre-authentication can be attacked with AS-REP roasting.")

    # 15. Other logon types and accounts worth a look
    newcred = [i for i in by_eid["4624"] if raw(rows[i], "LogonType") == "9"]
    if newcred:
        add("Low", "NewCredentials logon (logon type 9)", ", ".join(sorted({label(i) for i in newcred})[:5]),
            newcred, "Used by 'runas /netonly' and also by pass-the-hash tools.")
    admin = [i for i in by_eid["4624"] + by_eid["4625"] if account_name(rows[i]) == "administrator"]
    if admin:
        add("Low", "Built-in Administrator account used", "Administrator", admin,
            f"{len(admin)} logon event(s). Shared admin accounts make actions hard to attribute.")
    timechg = [i for i in by_eid["4616"] if is_person({**rows[i], "_data": {"SubjectUserName": raw(rows[i], "SubjectUserName")}})]
    if timechg:
        add("Low", "System time changed by a user", ", ".join(sorted({primary_account(rows[i]) for i in timechg})[:5]),
            timechg, "Changing the clock can be used to confuse log timelines.")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -len(f["rows"])))
    flags = defaultdict(set)
    for f in findings:
        for i in f["rows"]:
            flags[i].add(f["rule"])
    for i, r in enumerate(rows):
        r["Flags"] = "; ".join(sorted(flags.get(i, ())))
    return findings


# ============================================================================
#  HTML REPORT
# ============================================================================

CSS = """
:root {
  --page: #f3f5f6; --sheet: #ffffff; --ink: #1d2830; --muted: #5d6b75;
  --rule: #d6dde1; --band: #eef2f4; --accent: #0e6a70; --accent-soft: #d7eced;
  --fail: #a8261d; --fail-soft: #f8e3e1; --ok: #2d6e46; --warn: #8a5300; --warn-soft: #fbefd9;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --page: #15191c; --sheet: #1d2327; --ink: #e3e8eb; --muted: #9aa7b0;
    --rule: #334048; --band: #252d32; --accent: #5cc0c6; --accent-soft: #1f3a3c;
    --fail: #f08a80; --fail-soft: #3d2422; --ok: #7fc79a; --warn: #e8b45c; --warn-soft: #3a2e19;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
html { background: var(--page); }
body { margin: 0; color: var(--ink); background: var(--page);
  font: 15px/1.5 "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-variant-numeric: tabular-nums; }
main { max-width: 1400px; margin: 0 auto; padding: 32px 24px 64px; }
header.top { border-bottom: 3px solid var(--ink); padding-bottom: 16px; margin-bottom: 24px; }
header.top h1 { font-size: 28px; line-height: 1.2; margin: 0 0 6px; font-weight: 650; letter-spacing: -0.01em; }
header.top p { margin: 0; color: var(--muted); }
nav.tabs { display: flex; gap: 4px; margin: 0 0 20px; border-bottom: 1px solid var(--rule); }
nav.tabs button { font: inherit; font-weight: 600; background: none; border: 0; color: var(--muted);
  padding: 10px 16px; border-bottom: 3px solid transparent; margin-bottom: -1px; cursor: pointer; }
nav.tabs button[aria-selected="true"] { color: var(--ink); border-bottom-color: var(--accent); }
button:focus-visible, input:focus-visible, select:focus-visible, tr[tabindex]:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px; }
.ledger { display: grid; grid-template-columns: repeat(4, 1fr);
  border: 1px solid var(--rule); background: var(--sheet); margin-bottom: 28px; }
.ledger div { padding: 14px 16px; border-right: 1px solid var(--rule); border-bottom: 1px solid var(--rule); }
.ledger dt { color: var(--muted); font-size: 13px; }
.ledger dd { margin: 2px 0 0; font-size: 22px; font-weight: 650; }
.ledger dd.small { font-size: 15px; font-weight: 600; }
.ledger .fail dd { color: var(--fail); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(520px, 100%), 1fr)); gap: 28px; }
section.block h2 { font-size: 17px; margin: 0 0 4px; font-weight: 650; }
section.block p.note { margin: 0 0 8px; color: var(--muted); font-size: 13px; }
.scroll { overflow-x: auto; border: 1px solid var(--rule); background: var(--sheet); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
thead th { background: var(--band); font-weight: 600; white-space: nowrap; position: sticky; top: 0; }
td.num, th.num { text-align: right; white-space: nowrap; }
.summary tbody tr { cursor: pointer; }
.summary tbody tr:hover { background: var(--accent-soft); }
.summary td.num, .summary th.num { width: 150px; }
.share { display: block; height: 4px; background: var(--accent); margin: 4px 0 0 auto; min-width: 2px; opacity: .7; }
.controls { display: flex; flex-wrap: wrap; gap: 10px 14px; align-items: end; margin-bottom: 12px; }
.controls label { display: flex; flex-direction: column; font-size: 13px; color: var(--muted); gap: 3px; }
.controls label.check { flex-direction: row; align-items: center; gap: 6px; color: var(--ink); font-size: 14px; padding-bottom: 6px; }
input[type=search], select { font: inherit; font-size: 14px; padding: 6px 8px; border: 1px solid var(--rule);
  background: var(--sheet); color: var(--ink); }
input[type=search] { width: 280px; }
.btn { font: inherit; font-size: 14px; padding: 6px 12px; border: 1px solid var(--rule); background: var(--sheet);
  color: var(--ink); cursor: pointer; }
.btn:hover { border-color: var(--accent); }
.chip { display: none; align-items: center; gap: 8px; background: var(--accent-soft); padding: 6px 10px; font-size: 14px; }
.chip.on { display: inline-flex; }
.status-line { display: flex; justify-content: space-between; align-items: center; gap: 12px;
  margin: 10px 0; color: var(--muted); font-size: 14px; flex-wrap: wrap; }
.pager { display: flex; gap: 6px; align-items: center; }
#events th { cursor: pointer; user-select: none; }
#events th[aria-sort="ascending"]::after { content: " \\25B2"; font-size: 10px; }
#events th[aria-sort="descending"]::after { content: " \\25BC"; font-size: 10px; }
#events td { white-space: nowrap; max-width: 420px; overflow: hidden; text-overflow: ellipsis; }
#events td.wrap { white-space: normal; min-width: 320px; }
#events tbody tr:nth-child(even) { background: var(--band); }
#events tr.failure td:first-child { box-shadow: inset 3px 0 var(--fail); }
.res-fail { color: var(--fail); font-weight: 600; }
.res-ok { color: var(--ok); }
.empty { padding: 28px; text-align: center; color: var(--muted); }
.sev { display: inline-block; min-width: 64px; text-align: center; font-size: 12px; font-weight: 700;
  padding: 2px 8px; border: 1px solid currentColor; }
.sev-High { color: var(--fail); background: var(--fail-soft); }
.sev-Medium { color: var(--warn); background: var(--warn-soft); }
.sev-Low { color: var(--muted); }
.findings tbody tr { cursor: pointer; }
.findings tbody tr:hover { background: var(--accent-soft); }
.findings td.detail { min-width: 320px; }
.intro { max-width: 900px; color: var(--muted); margin: 0 0 16px; }
.ledger .warn dd { color: var(--warn); }
#events td.flag { color: var(--warn); font-weight: 600; }
footer { margin-top: 40px; color: var(--muted); font-size: 13px; }
[hidden] { display: none !important; }
@media (max-width: 640px) {
  main { padding: 20px 12px 48px; }
  .grid { grid-template-columns: 1fr; }
  .ledger { grid-template-columns: repeat(2, 1fr); }
  input[type=search] { width: 100%; }
}
"""

JS = r"""
const COLS = __COLS__;
const KEYN = __KEYN__;
const DATA = __DATA__;
const FINDINGS = __FINDINGS__;
const FAILED_IDS = new Set(__FAILED__);
const NUMERIC = new Set(["Event ID", "Record", "Source Port"]);
const idx = Object.fromEntries(COLS.map((c, i) => [c, i]));
const HAY = DATA.map(r => r.join("\u0001").toLowerCase());
const fmt = n => n.toLocaleString();

const state = { q: "", result: "", eid: "", failedOnly: false, flaggedOnly: false, pinned: null,
                sort: 0, dir: 1, page: 0, size: 100, all: false };
let view = [];

// ---------- tabs
const tabs = document.querySelectorAll("nav.tabs button");
function showTab(name) {
  tabs.forEach(b => b.setAttribute("aria-selected", b.dataset.tab === name));
  document.querySelectorAll("[data-panel]").forEach(p => p.hidden = p.dataset.panel !== name);
}
tabs.forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ---------- filter controls
const $ = id => document.getElementById(id);
function fillSelect(sel, values) {
  values.forEach(v => { const o = document.createElement("option"); o.value = v; o.textContent = v || "(none)"; sel.appendChild(o); });
}
fillSelect($("f-result"), [...new Set(DATA.map(r => r[idx["Result"]]))].sort());
fillSelect($("f-eid"), [...new Set(DATA.map(r => r[idx["Event ID"]]))].sort((a, b) => a - b));

let timer;
$("f-search").addEventListener("input", e => { clearTimeout(timer); timer = setTimeout(() => { state.q = e.target.value.trim().toLowerCase(); refresh(); }, 200); });
$("f-result").addEventListener("change", e => { state.result = e.target.value; refresh(); });
$("f-eid").addEventListener("change", e => { state.eid = e.target.value; refresh(); });
$("f-failed").addEventListener("change", e => { state.failedOnly = e.target.checked; refresh(); });
$("f-flagged").addEventListener("change", e => { state.flaggedOnly = e.target.checked; refresh(); });
$("f-size").addEventListener("change", e => { state.size = +e.target.value; state.page = 0; render(); });
$("f-cols").addEventListener("click", e => { state.all = !state.all; e.target.textContent = state.all ? "Show key columns" : "Show all columns"; render(); });
$("f-reset").addEventListener("click", () => {
  Object.assign(state, { q: "", result: "", eid: "", failedOnly: false, flaggedOnly: false, pinned: null });
  $("f-search").value = ""; $("f-result").value = ""; $("f-eid").value = ""; $("f-failed").checked = false;
  $("f-flagged").checked = false;
  refresh();
});
$("chip-clear").addEventListener("click", () => { state.pinned = null; refresh(); });
$("prev").addEventListener("click", () => { if (state.page > 0) { state.page--; render(); } });
$("next").addEventListener("click", () => { if ((state.page + 1) * state.size < view.length) { state.page++; render(); } });

// ---------- summary rows open matching events
document.querySelectorAll(".summary tbody tr").forEach(tr => {
  const go = () => {
    state.pinned = { filter: JSON.parse(tr.dataset.filter), label: tr.dataset.label };
    refresh(); showTab("events"); window.scrollTo(0, 0);
  };
  tr.addEventListener("click", go);
  tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
});

// ---------- findings open the events behind them
document.querySelectorAll(".findings tbody tr[data-finding]").forEach(tr => {
  const go = () => {
    state.pinned = { rows: new Set(FINDINGS[+tr.dataset.finding]), label: tr.dataset.label };
    refresh(); showTab("events"); window.scrollTo(0, 0);
  };
  tr.addEventListener("click", go);
  tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
});

function isFailed(r) { return r[idx["Result"]] === "Audit Failure" && FAILED_IDS.has(r[idx["Event ID"]]); }

function matches(r, i) {
  if (state.result !== "" && r[idx["Result"]] !== state.result) return false;
  if (state.eid !== "" && r[idx["Event ID"]] !== state.eid) return false;
  if (state.failedOnly && !isFailed(r)) return false;
  if (state.flaggedOnly && !r[idx["Flags"]]) return false;
  if (state.pinned && state.pinned.rows) { if (!state.pinned.rows.has(i)) return false; }
  else if (state.pinned) {
    for (const [k, v] of Object.entries(state.pinned.filter)) {
      if (k === "_failed") { if (!isFailed(r)) return false; }
      else if (r[idx[k]] !== v) return false;
    }
  }
  if (state.q && !HAY[i].includes(state.q)) return false;
  return true;
}

function refresh() {
  view = [];
  for (let i = 0; i < DATA.length; i++) if (matches(DATA[i], i)) view.push(DATA[i]);
  sortView();
  state.page = 0;
  const chip = $("chip");
  chip.classList.toggle("on", !!state.pinned);
  if (state.pinned) $("chip-text").textContent = "Showing: " + state.pinned.label;
  render();
}

function sortView() {
  const c = state.sort, d = state.dir, num = NUMERIC.has(COLS[c]);
  view.sort((a, b) => {
    let x = a[c], y = b[c];
    if (num) { x = +x || 0; y = +y || 0; return (x - y) * d; }
    return (x < y ? -1 : x > y ? 1 : 0) * d;
  });
}

function render() {
  const n = state.all ? COLS.length : KEYN;
  const head = $("ev-head"), body = $("ev-body");
  head.innerHTML = "";
  const tr = document.createElement("tr");
  for (let c = 0; c < n; c++) {
    const th = document.createElement("th");
    th.textContent = COLS[c];
    th.tabIndex = 0;
    th.setAttribute("aria-sort", c === state.sort ? (state.dir === 1 ? "ascending" : "descending") : "none");
    const act = () => { if (state.sort === c) state.dir *= -1; else { state.sort = c; state.dir = 1; } sortView(); state.page = 0; render(); };
    th.addEventListener("click", act);
    th.addEventListener("keydown", e => { if (e.key === "Enter") act(); });
    if (NUMERIC.has(COLS[c])) th.className = "num";
    tr.appendChild(th);
  }
  head.appendChild(tr);

  const start = state.page * state.size, rows = view.slice(start, start + state.size);
  const frag = document.createDocumentFragment();
  for (const r of rows) {
    const row = document.createElement("tr");
    if (r[idx["Result"]] === "Audit Failure") row.className = "failure";
    for (let c = 0; c < n; c++) {
      const td = document.createElement("td");
      const v = r[c];
      td.textContent = v;
      td.title = v;
      if (NUMERIC.has(COLS[c])) td.className = "num";
      if (COLS[c] === "Other Details") td.className = "wrap";
      if (COLS[c] === "Flags" && v) td.className = "flag";
      if (COLS[c] === "Result") td.className = v === "Audit Failure" ? "res-fail" : v === "Audit Success" ? "res-ok" : "";
      row.appendChild(td);
    }
    frag.appendChild(row);
  }
  body.innerHTML = "";
  body.appendChild(frag);
  $("empty").hidden = view.length > 0;
  $("count").textContent = view.length
    ? `Rows ${fmt(start + 1)}\u2013${fmt(start + rows.length)} of ${fmt(view.length)} matching events (${fmt(DATA.length)} total)`
    : `No events match these filters. Clear a filter to see more.`;
  $("prev").disabled = state.page === 0;
  $("next").disabled = start + state.size >= view.length;
}

refresh();
"""


def esc(v):
    return html.escape(str(v), quote=True)


def findings_html(findings):
    if not findings:
        return '<p class="empty">No suspicious patterns were found with the current settings.</p>'
    out = []
    for k, f in enumerate(findings):
        when = f["first"] if f["first"] == f["last"] else f"{f['first']} to {f['last']}"
        out.append(
            f'<tr tabindex="0" data-finding="{k}" data-label="{esc(f["rule"] + ": " + f["who"])}">'
            f'<td><span class="sev sev-{f["severity"]}">{f["severity"]}</span></td>'
            f'<td><strong>{esc(f["rule"])}</strong></td><td>{esc(f["who"])}</td>'
            f'<td>{esc(when)}</td><td class="num">{len(f["rows"]):,}</td>'
            f'<td class="detail">{esc(f["detail"])}</td></tr>')
    return ('<div class="scroll"><table class="findings"><thead><tr><th>Severity</th><th>Finding</th>'
            '<th>Account / source</th><th>When (UTC)</th><th class="num">Events</th><th>Why it matters</th>'
            f'</tr></thead><tbody>{"".join(out)}</tbody></table></div>')


def build_html(rows, sources, out_path, findings):
    sections = build_sections(rows)
    sev_counts = Counter(f["severity"] for f in findings)
    failed = sum(1 for r in rows if is_failed_logon(r))
    n_fail = sum(1 for r in rows if r["Result"] == "Audit Failure")
    n_ok = sum(1 for r in rows if r["Result"] == "Audit Success")
    accounts = len({primary_account(r) for r in rows if primary_account(r)})
    computers = len({r["Computer"] for r in rows if r["Computer"]})
    title = sources[0].name if len(sources) == 1 else f"{len(sources)} files in {sources[0].parent.name}"

    ledger = [
        ("Total events", f"{len(rows):,}", ""),
        ("First event (UTC)", rows[0]["Time (UTC)"], "small"),
        ("Last event (UTC)", rows[-1]["Time (UTC)"], "small"),
        ("Audit success", f"{n_ok:,}", ""),
        ("Audit failure", f"{n_fail:,}", "fail" if n_fail else ""),
        ("Failed logons", f"{failed:,}", "fail" if failed else ""),
        ("High-severity findings", f"{sev_counts['High']:,}", "fail" if sev_counts["High"] else ""),
        ("Other findings", f"{sev_counts['Medium'] + sev_counts['Low']:,}", "warn" if sev_counts["Medium"] else ""),
        ("Accounts", f"{accounts:,}", ""),
        ("Computers", f"{computers:,}", ""),
    ]
    ledger_html = "".join(
        f'<div class="{cls if cls in ("fail", "warn") else ""}"><dt>{esc(k)}</dt>'
        f'<dd class="{"small" if cls == "small" else ""}">{esc(v)}</dd></div>'
        for k, v, cls in ledger)

    blocks = []
    for s in sections:
        top = max((n for _, n, _ in s["items"]), default=1)
        head = "".join(f"<th>{esc(h)}</th>" for h in s["headers"]) + '<th class="num">Count</th>'
        if s["items"]:
            body = []
            for cells, n, flt in s["items"]:
                label = " / ".join(str(c) for c in cells)
                width = max(1, round(100 * n / top))
                tds = "".join(f"<td>{esc(c)}</td>" for c in cells)
                body.append(
                    f'<tr tabindex="0" data-filter="{esc(json.dumps(flt))}" '
                    f'data-label="{esc(s["title"] + ": " + label)}">{tds}'
                    f'<td class="num">{n:,}<span class="share" style="width:{width}%"></span></td></tr>')
            body = "".join(body)
        else:
            body = f'<tr><td colspan="{len(s["headers"]) + 1}" class="empty">None in this log.</td></tr>'
        note = f'<p class="note">{esc(s["note"])}</p>' if s["note"] else ""
        blocks.append(f'<section class="block"><h2>{esc(s["title"])}</h2>{note}'
                      f'<div class="scroll"><table class="summary"><thead><tr>{head}</tr></thead>'
                      f'<tbody>{body}</tbody></table></div></section>')

    data = [[primary_account(r) if c == "Primary Account" else r[c] for c in REPORT_COLUMNS] for r in rows]
    js = (JS.replace("__COLS__", json.dumps(REPORT_COLUMNS))
            .replace("__KEYN__", str(KEY_COLUMN_COUNT))
            .replace("__FAILED__", json.dumps(list(FAILED_LOGON_IDS)))
            .replace("__FINDINGS__", json.dumps([f["rows"] for f in findings], separators=(",", ":")))
            .replace("__DATA__", json.dumps(data, separators=(",", ":"), ensure_ascii=False)
                     .replace("</", "<\\/")))

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Event log report: {esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header class="top">
  <h1>Event log report: {esc(title)}</h1>
  <p>{len(rows):,} events from {esc(", ".join(s.name for s in sources))}. All times are UTC.
     Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}.</p>
</header>

<nav class="tabs" role="tablist">
  <button role="tab" data-tab="summary" aria-selected="true">Summary</button>
  <button role="tab" data-tab="suspicious" aria-selected="false">Suspicious activity ({len(findings)})</button>
  <button role="tab" data-tab="events" aria-selected="false">Events</button>
</nav>

<div data-panel="summary">
  <dl class="ledger">{ledger_html}</dl>
  <p class="note" style="color:var(--muted);margin:-12px 0 20px">Click any row below to see those events in the Events tab.</p>
  <div class="grid">{"".join(blocks)}</div>
</div>

<div data-panel="suspicious" hidden>
  <p class="intro">Patterns a security analyst would want to review, most serious first. Off-hours means
    {OFF_HOURS_START:02d}:00 to {OFF_HOURS_END:02d}:00 local time (UTC{UTC_OFFSET_HOURS:+d}). These are leads,
    not proof: click a finding to see the events behind it. Thresholds can be changed at the top of the script.</p>
  {findings_html(findings)}
</div>

<div data-panel="events" hidden>
  <div class="controls">
    <label>Search every field<input type="search" id="f-search" placeholder="Account, IP, computer, code..."></label>
    <label>Result<select id="f-result"><option value="">All</option></select></label>
    <label>Event ID<select id="f-eid"><option value="">All</option></select></label>
    <label class="check"><input type="checkbox" id="f-failed"> Failed logons only</label>
    <label class="check"><input type="checkbox" id="f-flagged"> Flagged events only</label>
    <label>Rows per page<select id="f-size"><option>50</option><option selected>100</option><option>250</option><option>500</option></select></label>
    <button class="btn" id="f-cols" type="button">Show all columns</button>
    <button class="btn" id="f-reset" type="button">Clear filters</button>
  </div>
  <div class="chip" id="chip"><span id="chip-text"></span><button class="btn" id="chip-clear" type="button">Remove</button></div>
  <div class="status-line"><span id="count"></span>
    <span class="pager"><button class="btn" id="prev" type="button">Previous</button><button class="btn" id="next" type="button">Next</button></span></div>
  <div class="scroll"><table id="events"><thead id="ev-head"></thead><tbody id="ev-body"></tbody></table>
    <div class="empty" id="empty" hidden>No events match these filters. Clear a filter to see more.</div></div>
  <p class="note" style="color:var(--muted);font-size:13px">Target User Name is the raw TargetUserName field from each event. Click a column heading to sort. Hover over a cut-off cell to see its full value.</p>
</div>

<footer>Descriptions come from the script's built-in reference for Windows Security, System, Remote Desktop, PowerShell, Task Scheduler, Defender and Sysmon events.</footer>
</main>
<script>{js}</script>
</body>
</html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)


# ============================================================================
#  MAIN
# ============================================================================

def main():
    ap = argparse.ArgumentParser(description="Decode Windows event log XML files into one HTML report.")
    ap.add_argument("path", nargs="?", help="XML file or folder of XML files")
    ap.add_argument("--lookup", metavar="CODE", help="look up an event ID, logon type, or status code")
    args = ap.parse_args()

    if args.lookup:
        lookup(args.lookup)
        return

    path_str = args.path or INPUT_PATH or pick_file_with_dialog()
    if not path_str:
        sys.exit("No file chosen. Set INPUT_PATH at the top of the script or pass a path.")

    files = resolve_inputs(path_str)
    rows = []
    for f in files:
        print(f"Processing {f} ...")
        rows.extend(parse_file(f))
    if not rows:
        sys.exit("No <Event> records found.")
    rows.sort(key=lambda r: r["_sort"])

    base = files[0] if len(files) == 1 else files[0].parent / files[0].parent.name
    out_path = base.with_name(base.stem + "_report.html")

    findings = detect_suspicious(rows)

    print()
    for line in summary_lines(rows):
        print(line)
    print(f"\n=== Suspicious activity: {len(findings)} finding(s) ===")
    for f in findings[:15]:
        print(f"  [{f['severity']:<6}] {f['rule']}: {f['who']} ({len(f['rows']):,} events)")
    if len(findings) > 15:
        print(f"  ...and {len(findings) - 15} more in the report.")

    start = time.time()
    try:
        build_html(rows, files, out_path, findings)
    except PermissionError:
        sys.exit(f"\nCould not save {out_path}. Check that the folder isn't read-only.")
    size_mb = out_path.stat().st_size / 1_048_576
    print(f"\nSaved all {len(rows):,} events to:\n  {out_path}   ({size_mb:.1f} MB, {time.time() - start:.1f}s)")
    if len(rows) > 400_000:
        print("  Note: this is a very large report; your browser may take a little while to open it.")

    if OPEN_WHEN_DONE:
        webbrowser.open(out_path.resolve().as_uri())


if __name__ == "__main__":
    main()
