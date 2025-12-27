control 'SV-84553' do
  title 'Exchange internal Receive connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) Receive connector is used by Exchange to send and receive messages from server to server using SMTP protocol. This setting controls the encryption strength used for client connections to the SMTP Receive connector. With this feature enabled, only clients capable of supporting secure communications will be able to send mail using this SMTP server. Where secure channels are required, encryption can also be selected. 

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from the client to the server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.  

Individually, channel security and encryption have been compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between the client and server.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, AuthMechanism

For each Receive connector, if the value of AuthMechanism is not set to Tls, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -AuthMechanism 'Tls'

Note: The <IdentityName> value must be in quotes.

Repeat the process for each Receive connector."
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70401r1_chk'
  tag severity: 'high'
  tag gid: 'V-69931'
  tag rid: 'SV-84553r1_rule'
  tag stig_id: 'EX13-EG-000340'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-76163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
