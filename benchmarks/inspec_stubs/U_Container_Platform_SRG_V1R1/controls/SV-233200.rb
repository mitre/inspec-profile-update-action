control 'SV-233200' do
  title 'The container platform must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Review the container platform configuration to determine if the platform is configured to prohibit the use of cached authenticators after an organization-defined time period. 

If the container platform is not configured to prohibit the use of cached authenticators after an organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the container platform to prohibit the use of cached authenticators after an organization-defined time period.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36136r599646_chk'
  tag severity: 'medium'
  tag gid: 'V-233200'
  tag rid: 'SV-233200r599647_rule'
  tag stig_id: 'SRG-APP-000400-CTR-000960'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-36104r599237_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
