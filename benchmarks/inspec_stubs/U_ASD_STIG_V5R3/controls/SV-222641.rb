control 'SV-222641' do
  title 'The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.'
  desc 'If the application does not use encryption and authenticate endpoints prior to establishing a communication channel and prior to transmitting encryption keys, these keys may be intercepted, and could be used to decrypt the traffic of the current session, leading to potential loss or compromise of DoD data.'
  desc 'check', 'If the application does not implement key exchange, this check is not applicable.

Identify all application or supporting infrastructure features using key exchange.

Verify the application is using FIPS-140-2 validated cryptographic modules for encryption of keys during key exchange.

If the application does not implement encryption for key exchange, this is a finding.'
  desc 'fix', 'Use encryption for key exchange.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24311r493831_chk'
  tag severity: 'medium'
  tag gid: 'V-222641'
  tag rid: 'SV-222641r879887_rule'
  tag stig_id: 'APSC-DV-003100'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24300r493832_fix'
  tag 'documentable'
  tag legacy: ['SV-84983', 'V-70361']
  tag cci: ['CCI-000201']
  tag nist: ['IA-5 (6)']
end
