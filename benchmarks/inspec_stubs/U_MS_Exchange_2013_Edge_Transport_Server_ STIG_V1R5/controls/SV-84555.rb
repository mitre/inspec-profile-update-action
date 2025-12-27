control 'SV-84555' do
  title 'Exchange internal Send connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. Several controls work together to provide security between internal servers. This setting controls the encryption method used for communications between servers. With this feature enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender. 

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsDomain

If the value of TlsDomain is not set to the value of the internal <'SMTP Domain'>, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -TlsDomain <'SMTP Domain'>

Note: The SMTP Domain is the internal SMTP domain within the organization."
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70403r1_chk'
  tag severity: 'high'
  tag gid: 'V-69933'
  tag rid: 'SV-84555r1_rule'
  tag stig_id: 'EX13-EG-000345'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-76165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
