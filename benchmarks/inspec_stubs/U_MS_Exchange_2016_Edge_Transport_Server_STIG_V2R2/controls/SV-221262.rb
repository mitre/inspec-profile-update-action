control 'SV-221262' do
  title 'Exchange internal Send connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. Several controls work together to provide security between internal servers. This setting controls the encryption method used for communications between servers. With this feature enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender. 

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', %q(Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsDomain

If the value of "TlsDomain" is not set to the value of the internal <'SMTP Domain'>, this is a finding.

Get-SendConnector | Select Name, Identity, DomainSecureEnabled

If the value of 'DomainSecureEnabled' is not set to 'True', this is a finding.)
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -TlsDomain <'SMTP Domain'>

Set-SendConnector -Identity <'ReceiveConnector'> -DomainSecureEnabled 'True'

Note: The SMTP Domain is the internal SMTP domain within the organization."
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22977r457887_chk'
  tag severity: 'high'
  tag gid: 'V-221262'
  tag rid: 'SV-221262r612603_rule'
  tag stig_id: 'EX16-ED-000690'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-22966r457888_fix'
  tag 'documentable'
  tag legacy: ['V-80603', 'SV-95313']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
