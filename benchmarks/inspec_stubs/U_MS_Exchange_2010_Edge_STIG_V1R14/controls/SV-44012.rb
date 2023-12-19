control 'SV-44012' do
  title 'Internal Send Connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. There are several controls that work together to provide security between internal servers. This setting controls the encryption method used for communications between servers.  With this feature  enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers.  While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.  

Individually, channel security and encryption can be compromised by attackers.  Used together, email becomes a more difficult target, and security is heightened.  Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsDomain

If the value of 'TlsDomain' is not set to the value of the internal <'SMTP Domain'>, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'SendConnector'> -TlsDomain <'SMTP Domain'>

<'SMTP Domain'> 

Note: 'SMTP Domain' is the internal SMTP domain within the organization."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41699r4_chk'
  tag severity: 'medium'
  tag gid: 'V-33592'
  tag rid: 'SV-44012r3_rule'
  tag stig_id: 'Exch-2-766'
  tag gtitle: 'Exch-2-766'
  tag fix_id: 'F-37484r4_fix'
  tag 'documentable'
end
