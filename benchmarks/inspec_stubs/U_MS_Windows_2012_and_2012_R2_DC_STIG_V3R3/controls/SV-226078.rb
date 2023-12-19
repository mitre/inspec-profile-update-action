control 'SV-226078' do
  title 'The directory server supporting (directly or indirectly) system access or resource authorization must run on a machine dedicated to that function.'
  desc 'Executing application servers on the same host machine with a directory server may substantially weaken the security of the directory server.  Web or database server applications usually require the addition of many programs and accounts increasing the attack surface of the computer. 

Some applications require the addition of privileged accounts providing potential sources of compromise.  Some applications (such as MS Exchange) may require the use of network ports or services conflicting with the directory server.  In this case, non-standard ports might be selected and this could interfere with intrusion detection or prevention services.'
  desc 'check', 'Review the roles and services the domain controller is running.
Run "services.msc" to display the Services console.

Determine if any running services are application components.

Examples of services indicating the presence of applications are: 
-DHCP Server for DHCP server
-IIS Admin Service for IIS web server
-Microsoft Exchange System Attendant for Exchange
-MSSQLServer for SQL Server.

If any application-related components have the "Started" status, this is a finding.

Installed roles can be displayed by viewing Server Roles in the Add (or Remove) Roles and Features wizard.  (Cancel before any changes are made.)

Determine if any additional server roles are installed.  A basic domain controller set up will include the following:
-Active Directory Domain Services
-DNS Server
-File and Storage Services

If any roles not requiring installation on a domain controller are installed, this is a finding. 

Supplemental Notes:
A Domain Name System (DNS) server integrated with the directory server (e.g., AD-integrated DNS) is an acceptable application.  However, the DNS server must comply with the DNS STIG security requirements.

Some directory servers utilize specialized web servers for administrative functions and databases for data management.  These web and database servers are permitted as long as they are dedicated to directory server support and only administrative users have access to them.'
  desc 'fix', 'Remove additional roles or applications such as web, database, and email from the domain controller.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27780r475557_chk'
  tag severity: 'medium'
  tag gid: 'V-226078'
  tag rid: 'SV-226078r794311_rule'
  tag stig_id: 'WN12-AD-000009-DC'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27768r475558_fix'
  tag 'documentable'
  tag legacy: ['SV-51183', 'V-8326']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
