control 'SV-43989' do
  title 'Internet facing receive connectors must offer TLS before using basic authentication.'
  desc 'Sending unencrypted email over the Internet increases the risk that messages can be intercepted or altered. Transport Layer Security (TLS) is designed to protect confidentiality and data integrity by encrypting email messages between servers and thereby reducing the risk of eavesdropping, interception, and alteration. This setting forces Exchange to offer TLS before using basic authentication.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector -Identity <'ServerUnderReview\\ReceiveConnector'> | Select AuthMechanism

If the value of 'AuthMechanism' is not set to 'Tls, BasicAuth, BasicAuthRequireTLS', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -AuthMechanism 'Tls, BasicAuth, BasicAuthRequireTLS'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33569'
  tag rid: 'SV-43989r1_rule'
  tag stig_id: 'Exch-2-724'
  tag gtitle: 'Exch-2-724'
  tag fix_id: 'F-37460r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
