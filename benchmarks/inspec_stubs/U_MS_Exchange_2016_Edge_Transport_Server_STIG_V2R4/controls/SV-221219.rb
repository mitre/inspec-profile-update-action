control 'SV-221219' do
  title 'Exchange Internet-facing Receive connectors must offer Transport Layer Security (TLS) before using basic authentication.'
  desc 'Sending unencrypted email over the Internet increases the risk that messages can be intercepted or altered. TLS is designed to protect confidentiality and data integrity by encrypting email messages between servers and thereby reducing the risk of eavesdropping, interception, and alteration. This setting forces Exchange to offer TLS before using basic authentication.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, AuthMechanism

For each receive connector, if the value of "AuthMechanism" is not set to "Tls, BasicAuth, BasicAuthRequireTLS", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -AuthMechanism 'Tls, BasicAuth, BasicAuthRequireTLS'

Note: The <IdentityName> value must be in single quotes.

Example only for the Identity: <ServerName>\\Frontend <ServerName>

Repeat the procedure for each receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22934r411783_chk'
  tag severity: 'medium'
  tag gid: 'V-221219'
  tag rid: 'SV-221219r612603_rule'
  tag stig_id: 'EX16-ED-000180'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-22923r411784_fix'
  tag 'documentable'
  tag legacy: ['SV-95229', 'V-80519']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
