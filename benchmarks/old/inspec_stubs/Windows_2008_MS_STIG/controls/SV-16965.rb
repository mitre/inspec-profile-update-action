control 'SV-16965' do
  title 'Unnecessary services are not disabled.'
  desc 'Unnecessary Services increase the attack surface of a system.  Some Services may be run under the local System Account, which generally has more permissions than required by the service.  Compromising a service could allow an intruder to obtain System permissions and open the system to a variety of attacks.'
  desc 'check', '2008 - Select “Start”
Right-click the “Computer” icon on the Start menu.
Select “Manage” from the drop-down menu.
Expand the “Services and Applications” object in the Tree window.
Select the “Services” object.

Alternately enter "Services.msc" in the run box.

Unnecessary Services increase the attack surface of a system.  This check verifies that unnecessary services are not enabled on a system.

Required services will vary between organizations, and will vary depending on the role of the individual system.  Organizations will develop their own list of services which will be documented and justified with the IAO.  The Site’s list will be provided for any security review.  Services that are common to multiple systems can be addressed in one document.  Exceptions for individual systems should be identified separately by system.

If the site hasn’t documented the services required for their system(s) this is a finding.

The following services have been specifically identified as required to be disabled.  If any of these are installed and not Disabled this is a finding.  (Only the IP Helper service is installed by default.)

Fax (fax)
IP Helper (iphlpsvc)
FTP Publishing Service (msftpsvc)
Peer Networking Identity Manager (p2pimsvc)
Simple TCP/IP Services (simptcp)
Telnet (tlntsvr)


Services for Windows Server 2008 roles are managed automatically, adding those necessary for a particular role.  The following tables list the default services for a baseline installation and those for common roles as a reference.

Default Installation
Name	Startup Type
Application Experience	Automatic
Application Information	Manual
Application Layer Gateway Service	Manual
Application Management	Manual
Background Intelligent Transfer Service	Automatic (Delayed Start)
Base Filtering Engine	Automatic
Certificate Propagation	Manual
CNG Key Isolation	Manual	
COM+ Event System	Automatic
COM+ System Application	Manual
Computer Browser	Disabled
Cryptographic Services	Automatic
DCOM Server Process Launcher	Automatic
Desktop Window Manager Session Manager	Automatic
DHCP Client	Automatic
Diagnostic Policy Service	Automatic
Diagnostic Service Host	Manual
Diagnostic System Host	Manual
Distributed Link Tracking Client	Automatic
Distributed Transaction Coordinator	Automatic (Delayed Start)
DNS Client	Automatic
Extensible Authentication Protocol	Manual
Function Discovery Provider Host	Manual
Function Discovery Resource Publication	Manual
Group Policy Client	Automatic
Health Key and Certificate Management	Manual
Human Interface Device Access	Manual
IKE and AuthIP IPsec Keying Modules	Automatic
Interactive Services Detection	Manual
Internet Connection Sharing (ICS)	Disabled
IP Helper	Disabled (Automatic is the default)
IPsec Policy Agent	Automatic
KtmRm for Distributed Transaction Coordinator	Automatic (Delayed Start)
Link-Layer Topology Discovery Mapper	Manual
Microsoft .NET Framework NGEN v2.0.50727_X86	Manual
Microsoft Fibre Channel Platform Registration Service	Manual
Microsoft iSCSI Initiator Service	Manual
Microsoft Software Shadow Copy Provider	Manual
Multimedia Class Scheduler	Manual
Netlogon	Manual
Network Access Protection Agent	Manual
Network Connections	Manual
Network List Service	Automatic
Network Location Awareness	Automatic
Network Store Interface Service	Automatic
Offline Files	Disabled
Performance Logs & Alerts	Manual
Plug and Play	Automatic
PnP-X IP Bus Enumerator	Disabled
Portable Device Enumerator Service	Manual
Print Spooler	Automatic
Problem Reports and Solutions Control Panel Support	Manual
Protected Storage	Manual
Remote Access Auto Connection Manager	Manual
Remote Access Connection Manager	Manual
Remote Procedure Call (RPC)	Automatic
Remote Procedure Call (RPC) Locator	Manual
Remote Registry	Automatic
Resultant Set of Policy Provider	Manual
Routing and Remote Access	Disabled
Secondary Logon	Automatic
Secure Socket Tunneling Protocol Service	Manual
Security Accounts Manager	Automatic
Server	Automatic
Shell Hardware Detection	Automatic
SL UI Notification Service	Manual
Smart Card	Manual
Smart Card Removal Policy	Manual
SNMP Trap	Manual
Software Licensing	Automatic
Special Administration Console Helper	Manual
SSDP Discovery	Disabled
Superfetch	Disabled
System Event Notification Service	Automatic
Task Scheduler	Automatic
TCP/IP NetBIOS Helper	Automatic
Telephony	Manual
Terminal Services	Automatic
Terminal Services Configuration	Manual
Terminal Services UserMode Port Redirector	Manual
Themes	Disabled
Thread Ordering Server	Manual
TPM Base Services	Automatic (Delayed Start)
UPnP Device Host	Disabled
User Profile Service	Automatic
Virtual Disk	Manual
Volume Shadow Copy	Manual
Windows Audio	Manual
Windows Audio Endpoint Builder	Manual
Windows Color System	Manual
Windows Driver Foundation - User-mode Driver Framework	Manual
Windows Error Reporting Service	Automatic
Windows Event Collector	Manual
Windows Event Log	Automatic
Windows Firewall	Automatic
Windows Installer	Manual
Windows Management Instrumentation	Automatic
Windows Modules Installer	Manual
Windows Remote Management (WS-Management)	Automatic (Delayed Start)
Windows Time	Automatic
Windows Update	Automatic (Delayed Start)
WinHTTP Web Proxy Auto-Discovery Service	Manual
Wired AutoConfig	Manual
WMI Performance Adapter	Manual
Workstation	Automatic

Services for Roles addressed in the Microsoft Windows Server 2008 Security Guide
These major Roles may include sub roles not addressed here.

Name	Startup Type
Active Directory Certificate Services	
Active Directory Certificate Services		Automatic
	
Active Directory Domain Services	
Active Directory Domain Services	Automatic
DFS Namespace	Automatic
DFS Replication	Automatic
Intersite Messaging	Automatic
Kerberos Key Distribution Center	Automatic
	
DHCP Server	
DHCP Server	Automatic
	
DNS Server	
DNS Server	Automatic
	
File Server	
Server	Automatic
Workstation	Automatic
	
Network Policy and Access Server	
Network Policy Server	Automatic (Delayed Start)
	
Print Server	
Print Spooler	Automatic
	
Terminal Services Server	
Terminal Server	Automatic
Terminal Services Configuration	Manual
Terminal Services UserMode Port Redirector	Manual
	
Web Server (IIS)	
World Wide Web Publishing Service	Automatic
Windows Process Activation 	Manual
Application Host Helper Service	Automatic
	

Documentable: Yes
Documentable Explanation: Services that are required should be documented with the IAO.'
  desc 'fix', 'Configure the system to disable any services that are not required.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-16654r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3487'
  tag rid: 'SV-16965r1_rule'
  tag gtitle: 'Unnecessary Services'
  tag fix_id: 'F-6001r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
