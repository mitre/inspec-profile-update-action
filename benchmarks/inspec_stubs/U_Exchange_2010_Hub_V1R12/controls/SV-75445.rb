control 'SV-75445' do
  title 'Internal Send Connectors must use an authentication level'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. There are several controls that work together to provide security between internal servers. This setting controls the encryption method used for communications between servers. With this feature enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender. 

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsAuthLevel

If the value of 'TlsAuthLevel' is not set to 'DomainValidation, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'SendConnector'> -TlsAuthLevel DomainValidation"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-61913r2_chk'
  tag severity: 'medium'
  tag gid: 'V-60981'
  tag rid: 'SV-75445r1_rule'
  tag stig_id: 'Exch-2-768'
  tag gtitle: 'Exch-2-768'
  tag fix_id: 'F-66713r1_fix'
  tag 'documentable'
end
