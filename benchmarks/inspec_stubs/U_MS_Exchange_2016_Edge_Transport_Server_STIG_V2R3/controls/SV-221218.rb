control 'SV-221218' do
  title 'Exchange internal Send connectors must use domain security (mutual authentication Transport Layer Security).'
  desc 'The Simple Mail Transfer Protocol (SMTP) connector is used by Exchange to send and receive messages from server to server. Several controls work together to provide security between internal servers. This setting controls the authentication method used for communications between servers. With this feature enabled, only servers capable of supporting domain authentication will be able to send and receive mail within the domain.

The use of secure communication prevents eavesdroppers from reading or modifying communications between mail clients and servers. While sensitive message bodies should be encrypted by the sender at the client, requiring a secure connection from server to server adds protection by encrypting the sender and recipient information that cannot be encrypted by the sender.  

Individually, channel security and encryption can be compromised by attackers. Used together, email becomes a more difficult target, and security is heightened. Failure to enable this feature gives eavesdroppers an opportunity to read or modify messages between servers.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, DomainSecureEnabled, DNSRoutingEnabled, RequireTLS, TlsAuthLevel 

For each send connector: 

If the send connector does not use a smarthost and the value of "DomainSecureEnabled" is not set to "True", this is a finding.

If the send connector does use a smarthost, "DomainSecureEnabled" will be set to "False".  

If the send connector does use a smarthost "DNSRoutingEnabled",  "RequireTLS", and "TlsAuthLevel" must be set.

If the send connector using a smart host has a value for “DNSRoutingEnabled” that is not set to “False”, this is a finding.

If the send connector using a smarthost has a value for “RequireTLS” that is not set to “True”, this is a finding.

If the send connector using a smarthost has a value for “TlsAuthLevel” that is not set to “DomainValidation”, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector <'IdentityName'> -DomainSecureEnabled $true

Note: The <IdentityName> value must be in single quotes.

Repeat the procedures for each send connector.

The following commands can be executed if smarthosts are used:

Set-SendConnector <'IdentityName'> -RequireTLS $true -DNSRoutingEnabled $False -TlsAuthLevel $DomainValidation"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22933r811172_chk'
  tag severity: 'medium'
  tag gid: 'V-221218'
  tag rid: 'SV-221218r811174_rule'
  tag stig_id: 'EX16-ED-000170'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-22922r811173_fix'
  tag 'documentable'
  tag legacy: ['SV-95227', 'V-80517']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
