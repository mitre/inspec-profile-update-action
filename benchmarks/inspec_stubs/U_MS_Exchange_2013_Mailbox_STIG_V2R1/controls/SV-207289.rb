control 'SV-207289' do
  title 'Exchange internal Receive connectors must use Domain Security (mutual authentication Transport Layer Security).'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. There are several controls that work together to provide security between internal servers. This setting controls the authentication method used for communications between servers. With this feature enabled, only servers capable of supporting domain authentication will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.  

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, DomainSecureEnabled

For each Receive connector, if the value of DomainSecureEnabled is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -DomainSecureEnabled $true

Note: The <IdentityName> value must be in quotes.

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7547r611670_chk'
  tag severity: 'medium'
  tag gid: 'V-207289'
  tag rid: 'SV-207289r615936_rule'
  tag stig_id: 'EX13-MB-000115'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-7547r611671_fix'
  tag 'documentable'
  tag legacy: ['SV-84607', 'V-69985']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
