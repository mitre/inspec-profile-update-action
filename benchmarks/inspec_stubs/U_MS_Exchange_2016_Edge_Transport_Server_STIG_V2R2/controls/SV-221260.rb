control 'SV-221260' do
  title 'Exchange internal Send connectors must use an authentication level.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. Several controls work together to provide security between internal servers. This setting controls the encryption method used for communications between servers. With this feature enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender. 

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsAuthLevel

If the value of "TlsAuthLevel" is not set to "DomainValidation", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -TlsAuthLevel DomainValidation"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22975r411906_chk'
  tag severity: 'medium'
  tag gid: 'V-221260'
  tag rid: 'SV-221260r612603_rule'
  tag stig_id: 'EX16-ED-000670'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-22964r411907_fix'
  tag 'documentable'
  tag legacy: ['SV-95311', 'V-80601']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
