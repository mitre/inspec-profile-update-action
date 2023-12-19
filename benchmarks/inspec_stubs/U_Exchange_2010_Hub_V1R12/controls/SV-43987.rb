control 'SV-43987' do
  title 'Internal Receive Connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) Receive Connector is used by Exchange to send and receive messages from server to server using SMTP protocol.  This setting controls the encryption strength used for client connections to the SMTP Receive Connector.  With this feature enabled, only clients capable of supporting secure communications will be able to send mail using this SMTP server.  Where secure channels are required, encryption can also be selected. 

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers.    While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from the client to the server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.  

Individually, channel security and encryption have been compromised by attackers.  Used together, email becomes a more difficult target, and security is heightened.  Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between the client and server.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, AuthMechanism

If the value of 'AuthMechanism' is not set to 'Tls', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -AuthMechanism 'Tls'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33567'
  tag rid: 'SV-43987r1_rule'
  tag stig_id: 'Exch-2-718'
  tag gtitle: 'Exch-2-718'
  tag fix_id: 'F-37459r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
