control 'SV-18389' do
  title 'Unnecessary services are not disabled.'
  desc 'Unnecessary services increase the attack surface of a system.  Some services may be run under the local System account, which generally has more permissions than required by the service.  Compromising a service could allow an intruder to obtain system permissions and open the system to a variety of attacks.'
  desc 'check', 'Select “Start”.
Right-click the “My Computer” icon on the Start menu or the desktop.
Select “Manage” from the drop-down menu.
Expand the “Services and Applications” object in the Tree window.
Select the “Services” object.

If services listed below are found, are not disabled (or set to manual in a few cases), and the site does not have documented exceptions for these, this is a finding.  
 
Documentable Explanation: Required services should be documented with the IAO.

Alerter
Background Intelligent Transfer Service (Manual)
ClipBook
Computer Browser
Error Reporting Service
Fast User Switching Compatibility
Fax
FTP Publishing Service
IIS Admin Service
Indexing Service
IPv6 Helper Service
Messenger
NetMeeting Remote Desktop Sharing
Network DDE
Network DDE DSDM
Routing and Remote Access
Simple Network Management Protocol (SNMP) Service
Simple Network Management Protocol (SNMP) Trap
SSDP Discovery Service
Task Scheduler - See separate vulnerability WINSV-000106/V-30037
Telnet
Terminal Services
Universal Plug and Play Device Host
WebClient
Wireless Zero Configuration
WMI Performance Adapter (Manual)
World Wide Web Publishing Service'
  desc 'fix', 'Configure the system to disable any services that are not required.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-38510r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3487'
  tag rid: 'SV-18389r1_rule'
  tag gtitle: 'Unnecessary Services'
  tag fix_id: 'F-6001r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
