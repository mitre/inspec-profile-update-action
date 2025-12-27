control 'SV-226252' do
  title 'Necessary services must be documented to maintain a baseline to determine if additional, unnecessary services have been added to a system.'
  desc 'Unnecessary services increase the attack surface of a system. Some services may be run under the local System account, which generally has more permissions than required by the service.  Compromising a service could allow an intruder to obtain system permissions and open the system to a variety of attacks.'
  desc 'check', %q(Required services will vary between organizations, and on the role of the individual system.  Organizations will develop their own list of services which will be documented and justified with the ISSO.  The site's list will be provided for any security review.  Services common to multiple systems can be addressed in one document.  Exceptions for individual systems should be identified separately by system.

Individual services specifically required to be disabled per the STIG are identified in separate requirements.

If the site has not documented the services required for their system(s), this is a finding.

The following can be used to view the services on a system:
Run "Services.msc".

Services for Windows Server 2012 roles are managed automatically, adding those necessary for a particular role.  The following lists the default services for a baseline installation as a reference. This can be used as a basis for documenting the services necessary.

Default Installation
Name - Startup Type
Application Experience - Manual (Trigger Start)
Application Identity - Manual (Trigger Start)
Application Information - Manual
Application Layer Gateway Service - Manual
Application Management - Manual
Background Intelligent Transfer Service - Automatic (Delayed Start)
Background Tasks Infrastructure Service - Automatic
Base Filtering Engine - Automatic
Certificate Propagation - Manual
CNG Key Isolation - Manual (Trigger Start)
COM+ Event System - Automatic
COM+ System Application - Manual
Computer Browser - Disabled
Credential Manager - Manual
Cryptographic Services - Automatic
DCOM Server Process Launcher - Automatic
Device Association Service - Manual (Trigger Start)
Device Install Service - Manual (Trigger Start)
Device Setup Manager - Manual (Trigger Start)
DHCP Client - Automatic
Diagnostic Policy Service - Automatic (Delayed Start)
Diagnostic Service Host - Manual
Diagnostic System Host - Manual
Distributed Link Tracking Client - Automatic
Distributed Transaction Coordinator - Automatic (Delayed Start)
DNS Client - Automatic (Trigger Start)
Encrypting File System (EFS) - Manual (Trigger Start)
Extensible Authentication Protocol - Manual
Function Discovery Provider Host - Manual
Function Discovery Resource Publication - Manual
Group Policy Client - Automatic (Trigger Start)
Health Key and Certificate Management - Manual
Human Interface Device Access - Manual (Trigger Start)
Hyper-V Data Exchange Service - Manual (Trigger Start)
Hyper-V Guest Shutdown Service - Manual (Trigger Start)
Hyper-V Heartbeat Service - Manual (Trigger Start)
Hyper-V Remote Desktop Virtualization Service - Manual (Trigger Start)
Hyper-V Time Synchronization Service - Manual (Trigger Start)
Hyper-V Volume Shadow Copy Requestor - Manual (Trigger Start)
IKE and AuthIP IPsec Keying Modules - Manual (Trigger Start)
Interactive Services Detection - Manual
Internet Connection Sharing (ICS) - Disabled
IP Helper - Automatic
IPsec Policy Agent - Manual (Trigger Start)
KDC Proxy Server service (KPS) - Manual
KtmRm for Distributed Transaction Coordinator - Manual (Trigger Start)
Link-Layer Topology Discovery Mapper - Manual
Local Session Manager - Automatic
Microsoft iSCSI Initiator Service - Manual
Microsoft Software Shadow Copy Provider - Manual
Multimedia Class Scheduler - Manual
Net.Tcp Port Sharing Service - Disabled
Netlogon - Manual
Network Access Protection Agent - Manual
Network Connections - Manual
Network Connectivity Assistant - Manual (Trigger Start)
Network List Service - Manual
Network Location Awareness - Automatic
Network Store Interface Service - Automatic
Optimize drives - Manual
Performance Counter DLL Host - Manual
Performance Logs & Alerts - Manual
Plug and Play - Manual
Portable Device Enumerator Service - Manual (Trigger Start)
Power - Automatic
Print Spooler - Automatic
Printer Extensions and Notifications - Manual
Problem Reports and Solutions Control Panel Support - Manual
Remote Access Auto Connection Manager - Manual
Remote Access Connection Manager - Manual
Remote Desktop Configuration - Manual
Remote Desktop Services - Manual
Remote Desktop Services UserMode Port Redirector - Manual
Remote Procedure Call (RPC) - Automatic
Remote Procedure Call (RPC) Locator - Manual
Remote Registry - Automatic (Trigger Start)
Resultant Set of Policy Provider - Manual
Routing and Remote Access - Disabled
RPC Endpoint Mapper - Automatic
Secondary Logon - Manual
Secure Socket Tunneling Protocol Service - Manual
Security Accounts Manager - Automatic
Server - Automatic
Shell Hardware Detection - Automatic
Smart Card - Disabled
Smart Card Removal Policy - Manual
SNMP Trap - Manual
Software Protection - Automatic (Delayed Start, Trigger Start)
Special Administration Console Helper - Manual
Spot Verifier - Manual (Trigger Start)
SSDP Discovery - Disabled
Superfetch - Manual
System Event Notification Service - Automatic
Task Scheduler - Automatic
TCP/IP NetBIOS Helper - Automatic (Trigger Start)
Telephony - Manual
Themes - Automatic
Thread Ordering Server - Manual
UPnP Device Host - Disabled
User Access Logging Service - Automatic (Delayed Start)
User Profile Service - Automatic
Virtual Disk - Manual
Volume Shadow Copy - Manual
Windows All-User Install Agent - Manual (Trigger Start)
Windows Audio - Manual
Windows Audio Endpoint Builder - Manual
Windows Color System - Manual
Windows Driver Foundation - User-mode Driver Framework - Manual (Trigger Start)
Windows Error Reporting Service - Manual (Trigger Start)
Windows Event Collector - Manual
Windows Event Log - Automatic
Windows Firewall - Automatic
Windows Font Cache Service - Automatic
Windows Installer - Manual
Windows Licensing Monitoring Service - Automatic
Windows Management Instrumentation - Automatic
Windows Modules Installer - Manual
Windows Remote Management (WS-Management) - Automatic
Windows Store Service (WSService) - Manual (Trigger Start)
Windows Time - Manual (Trigger Start)
Windows Update - Manual
WinHTTP Web Proxy Auto-Discovery Service - Manual
Wired AutoConfig - Manual
WMI Performance Adapter - Manual
Workstation - Automatic)
  desc 'fix', 'Document the services required for the system to operate.  Remove or disable any services that are not required.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27954r476600_chk'
  tag severity: 'medium'
  tag gid: 'V-226252'
  tag rid: 'SV-226252r569184_rule'
  tag stig_id: 'WN12-GE-000021'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27942r476601_fix'
  tag 'documentable'
  tag legacy: ['SV-52218', 'V-3487']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
