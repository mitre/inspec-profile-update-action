control 'SV-228416' do
  title 'Exchange must use encryption for Outlook Web App (OWA) access.'
  desc 'This setting controls whether client machines should be forced to use secure channels to communicate with this virtual directory. If this feature is enabled, clients will only be able to communicate with the directory if they are capable of supporting secure communication with the server.

The use of secure communication prevents eavesdroppers from reading or modifying communications between servers and clients. The network and DMZ STIG identify criteria for OWA and Public Folder configuration in the network, including Common Access Card (CAC)-enabled pre-authentication through an application firewall proxy.

Failure to require secure connections on a website increases the potential for unintended eavesdropping or data loss.'
  desc 'check', 'Open a Exchange Management Shell and enter the following command:

Get-OwaVirtualDirectory | select internalurl, externalurl

If the value returned is not https://, this is a finding.'
  desc 'fix', 'Configure the OWA site to require SSL port 443.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30649r684256_chk'
  tag severity: 'medium'
  tag gid: 'V-228416'
  tag rid: 'SV-228416r879519_rule'
  tag stig_id: 'EX16-MB-002910'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-30634r497045_fix'
  tag 'documentable'
  tag legacy: ['SV-95431', 'V-80721']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
