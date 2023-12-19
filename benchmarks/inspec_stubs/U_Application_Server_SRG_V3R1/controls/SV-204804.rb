control 'SV-204804' do
  title 'The application server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'When the application server is using PKI authentication, a local revocation cache must be stored for instances when the revocation cannot be authenticated through the network, but if cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Review application server documentation to ensure the application server prohibits the use of cached authenticators after an organization-defined timeframe.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to prohibit the use of cached authenticators after an organization-defined timeframe.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4924r283053_chk'
  tag severity: 'medium'
  tag gid: 'V-204804'
  tag rid: 'SV-204804r508029_rule'
  tag stig_id: 'SRG-APP-000400-AS-000246'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-4924r283054_fix'
  tag 'documentable'
  tag legacy: ['V-57513', 'SV-71789']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
