control 'SV-207290' do
  title 'Exchange internal Send connectors must require encryption.'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. There are several controls that work together to provide security between internal servers. This setting controls the encryption method used for communications between servers. With this feature enabled, only servers capable of supporting Transport Layer Security (TLS) will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender. 

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the internal SMTP Domain.

Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, TlsDomain

For each Send connector, if the value of TlsDomain is not set to the value of the internal <SMTP Domain>, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -TlsDomain <'SMTP Domain'>

Note: The <IdentityName> and <SMTP Domain> values must be in quotes.

Repeat the procedure for each Send connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7548r393383_chk'
  tag severity: 'medium'
  tag gid: 'V-207290'
  tag rid: 'SV-207290r615936_rule'
  tag stig_id: 'EX13-MB-000120'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-7548r393384_fix'
  tag 'documentable'
  tag legacy: ['SV-84609', 'V-69987']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
