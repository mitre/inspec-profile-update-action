control 'SV-43988' do
  title 'External Receive Connectors must be Domain Secure Enabled.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. There are several controls that work together to provide security between internal servers. This setting controls the authentication method used for communications between servers.  With this feature enabled, messages can be securely passed from a partner domain securely. 

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers.    While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.  

Individually, channel security and encryption can be compromised by attackers.  Used together, email becomes a more difficult target, and security is heightened.  Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, DomainSecureEnabled

If the value of 'DomainSecureEnabled' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -DomainSecureEnabled 'True'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41674r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33568'
  tag rid: 'SV-43988r1_rule'
  tag stig_id: 'Exch-2-721'
  tag gtitle: 'Exch-2-721'
  tag fix_id: 'F-40289r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
