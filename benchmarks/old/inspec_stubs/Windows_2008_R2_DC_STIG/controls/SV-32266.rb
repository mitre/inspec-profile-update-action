control 'SV-32266' do
  title 'Services will be documented and unnecessary services will not be installed or will be disabled.'
  desc 'Unnecessary services increase the attack surface of a system.  Some services may be run under the local System account, which generally has more permissions than required by the service.  Compromising a service could allow an intruder to obtain system permissions and open the system to a variety of attacks.'
  desc 'check', 'Required services will vary between organizations, and on the role of the individual system. Organizations will develop their own list of services which will be documented and justified with the IAO. The Site’s list will be provided for any security review. Services common to multiple systems can be addressed in one document. Exceptions for individual systems should be identified separately by system.

Individual services specifically required to be disabled per the STIG are identified in separate requirements.

If the site has not documented the services required for their system(s), this is a finding.

The following can be used to view the services on a system:
Select “Start”.
Select “Run”.
Enter "Services.msc" in the run box.
Respond to any User Account Control prompts.


Services for Windows Server 2008 R2 roles are managed automatically, adding those necessary for a particular role. The following tables list the default services for a baseline installation and those for common roles as a reference.  This can be used as a basis for documenting the services necessary.

Default Installation
Name - Startup Type
Application Experience - Manual
Application Identity - Manual
Application Information - Manual
Application Layer Gateway Service - Manual
Application Management - Manual
Background Intelligent Transfer Service - Manual
Base Filtering Engine - Automatic
Certificate Propagation - Manual
CNG Key Isolation - Manual       
COM+ Event System - Automatic
COM+ System Application - Manual
Computer Browser - Disabled
Credential Manager - Manual
Cryptographic Services - Automatic
DCOM Server Process Launcher - Automatic
Desktop Window Manager Session Manager - Automatic
DHCP Client - Automatic
Diagnostic Policy Service – Automatic (Delayed Start)
Diagnostic Service Host - Manual
Diagnostic System Host – Manual
Disk Defragmenter - Manual
Distributed Link Tracking Client - Automatic
Distributed Transaction Coordinator - Automatic (Delayed Start)
DNS Client - Automatic
Encrypting File System (EFS) - Manual
Extensible Authentication Protocol - Manual
Function Discovery Provider Host - Manual
Function Discovery Resource Publication - Manual
Group Policy Client - Automatic
Health Key and Certificate Management - Manual
Human Interface Device Access - Manual
IKE and AuthIP IPsec Keying Modules - Manual
Interactive Services Detection - Manual
Internet Connection Sharing (ICS) - Disabled
IP Helper - Automatic
IPsec Policy Agent - Manual
KtmRm for Distributed Transaction Coordinator - Manual
Link-Layer Topology Discovery Mapper - Manual
Microsoft .NET Framework NGEN v2.0.50727_X64 - Manual
Microsoft .NET Framework NGEN v2.0.50727_X86 - Manual
Microsoft Fibre Channel Platform Registration Service - Manual
Microsoft iSCSI Initiator Service - Manual
Microsoft Software Shadow Copy Provider - Manual
Multimedia Class Scheduler - Manual
Netlogon - Manual
Network Access Protection Agent - Manual
Network Connections - Manual
Network List Service - Manual
Network Location Awareness - Automatic
Network Store Interface Service - Automatic
Performance Counter DLL Host - Manual
Performance Logs & Alerts - Manual
Plug and Play - Automatic
PnP-X IP Bus Enumerator - Disabled
Portable Device Enumerator Service - Manual
Power - Automatic
Print Spooler - Automatic
Problem Reports and Solutions Control Panel Support - Manual
Protected Storage - Manual
Remote Access Auto Connection Manager - Manual
Remote Access Connection Manager - Manual
Remote Desktop Configuration - Manual
Remote Desktop Services - Manual
Remote Desktop Services UserMode Port Redirector - Manual
Remote Procedure Call (RPC) - Automatic
Remote Procedure Call (RPC) Locator - Manual
Remote Registry - Automatic
Resultant Set of Policy Provider - Manual
Routing and Remote Access - Disabled
RPC Endpoint Mapper - Automatic
Secondary Logon - Manual
Secure Socket Tunneling Protocol Service - Manual
Security Accounts Manager - Automatic
Server - Automatic 
Shell Hardware Detection - Automatic
Smart Card - Manual
Smart Card Removal Policy - Automatic (Manual is the default)
SNMP Trap - Manual
Software Protection - Automatic (Delayed Start)
Special Administration Console Helper - Manual
SPP Notification Service - Manual
SSDP Discovery - Disabled
System Event Notification Service - Automatic
Task Scheduler - Automatic
TCP/IP NetBIOS Helper - Automatic
Telephony - Manual
Thread Ordering Server - Manual
TP AutoConnect Service - Manual
TPM Base Services - Manual
UPnP Device Host - Disabled
User Profile Service - Automatic
Virtual Disk - Manual
Volume Shadow Copy - Manual
Windows Audio - Manual
Windows Audio Endpoint Builder - Manual
Windows Color System - Manual
Windows Driver Foundation - User-mode Driver Framework - Manual
Windows Error Reporting Service - Manual
Windows Event Collector - Manual
Windows Event Log - Automatic
Windows Firewall - Automatic
Windows Font Cache Service - Manual
Windows Installer - Manual
Windows Management Instrumentation - Automatic
Windows Modules Installer - Manual
Windows Remote Management (WS-Management) - Automatic (Delayed Start)
Windows Time - Automatic
Windows Update - Automatic (Delayed Start)
WinHTTP Web Proxy Auto-Discovery Service - Manual
Wired AutoConfig - Manual
WMI Performance Adapter - Manual
Workstation – Automatic

The following services for roles are addressed in the Microsoft Windows Server 2008 R2 Security Guide, Windows Server 2008 R2 Attack Service Reference.xlsx.  These major roles may include sub-roles not addressed here.

Name - Startup Type
Active Directory Certificate Services
Active Directory Certificate Services - Automatic
      
Active Directory Domain Services
Active Directory Domain Services - Automatic
Active Directory Web Services - Automatic
DFS Namespace - Automatic
DFS Replication - Automatic
DNS Server - Automatic
Intersite Messaging - Automatic
Kerberos Key Distribution Center - Automatic
Net.Tcp Port Sharing Service - Disabled
Windows CardSpace - Manual
Windows Presentation Foundation Font Cache 3.0.0.0 - Manual
      
DHCP Server
DHCP Server - Automatic
      
DNS Server
DNS Server - Automatic
      
File Server
Server - Automatic 
Workstation - Automatic

Hyper-V Server
Hyper-V Image Management Service - Automatic
Hyper-V Networking Management Service - Automatic
Virtual Machine Management Service - Automatic
      
Network Policy and Access Server
Network Policy Server - Automatic (Delayed Start)
      
Print Server
Print Spooler - Automatic
      
Remote Desktop Services Server
Remote Desktop Configuration - Manual
Remote Desktop Services - Automatic
Remote Desktop Services UserMode Port - Manual
      
Web Server (IIS)
Application Host Helper Service - Automatic
Windows Process Activation - Manual
World Wide Web Publishing Service - Automatic'
  desc 'fix', 'Document the services required for the system to operate.  Remove or disable any services that are not required.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32712r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3487'
  tag rid: 'SV-32266r2_rule'
  tag gtitle: 'Unnecessary Services'
  tag fix_id: 'F-28959r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
