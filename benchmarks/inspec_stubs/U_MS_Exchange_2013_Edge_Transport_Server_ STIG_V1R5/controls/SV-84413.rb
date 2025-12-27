control 'SV-84413' do
  title 'Exchange external Receive connectors must be domain secure-enabled.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. Several controls work together to provide security between internal servers. This setting controls the authentication method used for communications between servers. With this feature enabled, messages can be securely passed from a partner domain securely.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, DomainSecureEnabled

For each Receive connector, if the value of DomainSecureEnabled is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -DomainSecureEnabled $true

Note: The <IdentityName> value must be in single quotes.

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69791'
  tag rid: 'SV-84413r1_rule'
  tag stig_id: 'EX13-EG-000025'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-76003r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
