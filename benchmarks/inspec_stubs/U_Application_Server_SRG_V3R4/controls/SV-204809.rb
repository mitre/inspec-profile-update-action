control 'SV-204809' do
  title 'The application server must conform to FICAM-issued profiles.'
  desc 'Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

This requirement addresses open identity management standards.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server conforms to FICAM-issued profiles.

If the application server does not conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'Configure the application server to conform to FICAM-issued profiles.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4929r283068_chk'
  tag severity: 'medium'
  tag gid: 'V-204809'
  tag rid: 'SV-204809r879778_rule'
  tag stig_id: 'SRG-APP-000405-AS-000250'
  tag gtitle: 'SRG-APP-000405'
  tag fix_id: 'F-4929r283069_fix'
  tag 'documentable'
  tag legacy: ['SV-71797', 'V-57521']
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
