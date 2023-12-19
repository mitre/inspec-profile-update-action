control 'SV-234766' do
  title 'Exchange must use Encryption for OWA access.'
  desc 'This setting controls whether client machines should be forced to use secure channels to communicate with this virtual directory. If this feature is enabled, clients will only be able to communicate with the directory if they are capable of supporting secure communication with the server.

The use of secure communication prevents eavesdroppers from reading or modifying communications between servers and clients. The network and DMZ STIG identify criteria for OWA and Public Folder configuration in the network, including CAC enabled pre-authentication through an application firewall proxy.

Failure to require secure connections on a web site increases the potential for unintended eavesdropping or data loss.'
  desc 'check', 'Open a Windows PowerShell and enter the following command:

Import-module webadministration
Enter cd “IIS:”
At the IIS: prompt, enter cd Sites
At the Sites: prompt, enter cd “Default Web Site”
At the “Default Web Site”: prompt, enter cd owa

At the IIS:\\Sites\\Default Web Site\\owa>: prompt, enter Get-WebConfigurationProperty -filter /system.webServer/security/access -name sslflags

If the value returned is not Ssl,Ssl128, this is a finding.'
  desc 'fix', 'Configure the OWA site to require SSL port 443.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37952r617237_chk'
  tag severity: 'medium'
  tag gid: 'V-234766'
  tag rid: 'SV-234766r617239_rule'
  tag stig_id: 'EX13-CA-000010'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37915r617238_fix'
  tag 'documentable'
  tag legacy: ['SV-84339', 'V-69717']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
