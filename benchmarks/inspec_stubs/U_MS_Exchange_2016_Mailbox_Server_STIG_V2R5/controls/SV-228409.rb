control 'SV-228409' do
  title 'Exchange Internal Send connectors must use an authentication level.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. Several controls work together to provide security between internal servers. This setting controls the encryption method used for communications between servers. With this feature enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender. 

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsAuthLevel

For each Send connector, if the value of "TlsAuthLevel" is not set to "DomainValidation", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -TlsAuthLevel DomainValidation

Note: The <IdentityName> value must be in single quotes.

Repeat the procedure for each Send connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30642r497023_chk'
  tag severity: 'medium'
  tag gid: 'V-228409'
  tag rid: 'SV-228409r879806_rule'
  tag stig_id: 'EX16-MB-000660'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-30627r497024_fix'
  tag 'documentable'
  tag legacy: ['SV-95461', 'V-80751']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
