control 'SV-84439' do
  title 'Exchange Internet-facing Receive connectors must offer Transport Layer Security (TLS) before using basic authentication.'
  desc 'Sending unencrypted email over the Internet increases the risk that messages can be intercepted or altered. TLS is designed to protect confidentiality and data integrity by encrypting email messages between servers and thereby reducing the risk of eavesdropping, interception, and alteration. This setting forces Exchange to offer TLS before using basic authentication.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, AuthMechanism

For each Receive connector, if the value of AuthMechanism is not set to Tls, BasicAuth, BasicAuthRequireTLS, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -AuthMechanism 'Tls, BasicAuth, BasicAuthRequireTLS'

Note: The <IdentityName> value must be in quotes.

Example only for the Identity: <ServerName>\\Frontend <ServerName>

Repeat the procedure for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69817'
  tag rid: 'SV-84439r1_rule'
  tag stig_id: 'EX13-EG-000090'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-76047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
