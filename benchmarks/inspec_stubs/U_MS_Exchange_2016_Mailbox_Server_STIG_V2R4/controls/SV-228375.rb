control 'SV-228375' do
  title 'Exchange internal Receive connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) Receive connector is used by Exchange to send and receive messages from server to server using SMTP protocol. This setting controls the encryption strength used for client connections to the SMTP Receive connector. With this feature enabled, only clients capable of supporting secure communications will be able to send mail using this SMTP server. Where secure channels are required, encryption can also be selected. 

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from the client to the server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.

Individually, channel security and encryption have been compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between the client and server.
Multiple values can be separated by commas, but some values have dependencies and exclusions. AuthMechanism may include other mechanisms as long as the "Tls" is identified.
•	Only use the value "None" by itself.
•	The value "BasicAuthRequireTLS" requires the values "BasicAuth" and "Tls".
•	The only other value that can be used with ExternalAuthoritative is "Tls".
•	The value "Tls" is required when the value of the RequireTLS parameter is "$true".
•	The value "ExternalAuthoritative" requires the value of the PermissionGroups parameter be set to "ExchangeServers".'
  desc 'check', 'Note: AuthMechanism may include other mechanisms as long as the "Tls" is identified.

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, AuthMechanism

For each Receive connector, if the value of "AuthMechanism" is not set to "Tls", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -AuthMechanism 'Tls'

Note: The <IdentityName> value must be in single quotes.

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30608r572123_chk'
  tag severity: 'medium'
  tag gid: 'V-228375'
  tag rid: 'SV-228375r612748_rule'
  tag stig_id: 'EX16-MB-000220'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-30593r496922_fix'
  tag 'documentable'
  tag legacy: ['SV-95375', 'V-80665']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
