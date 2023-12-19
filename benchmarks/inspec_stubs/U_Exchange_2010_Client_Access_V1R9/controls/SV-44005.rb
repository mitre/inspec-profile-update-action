control 'SV-44005' do
  title 'Encryption must be used for OWA access.'
  desc 'This setting controls whether client machines should be forced to use secure channels to communicate with this virtual directory.  If this feature is enabled, clients will only be able to communicate with the directory if they are capable of supporting secure communication with the server.

The use of secure communication prevents eavesdroppers from reading or modifying communications between servers and clients.   The network and DMZ STIG identify criteria for OWA and Public Folder configuration in the network, including CAC enabled pre-authentication through an application firewall proxy.

Failure to require secure connections on a web site increases the potential for unintended eavesdropping or data loss.'
  desc 'check', 'Open the Windows PowerShell Modules and enter the following command:

Import-module webadministration
IIS:
cd Sites
cd “Default Web Site”
cd owa

PS IIS:\\Sites\\Default Web Site\\owa> Get-WebConfigurationProperty -filter /system.webServer/security/access -name sslflags

Review the result and verify only TLSv1.0 or higher is returned. If not, this is a finding.'
  desc 'fix', 'Configure the OWA site to require SSL port 443.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41692r3_chk'
  tag severity: 'medium'
  tag gid: 'V-33585'
  tag rid: 'SV-44005r3_rule'
  tag stig_id: 'Exch-1-203'
  tag gtitle: 'Exch-1-203'
  tag fix_id: 'F-37477r1_fix'
  tag 'documentable'
end
