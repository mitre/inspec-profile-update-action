control 'SV-233076' do
  title 'The container platform application program interface (API) must uniquely identify and authenticate users.'
  desc 'The container platform requires user accounts to perform container platform tasks. These tasks are often performed through the container platform API. Protecting the API from users who are not authorized or authenticated is essential to keep the container platform stable. Protection of platform and application data and enhances the protections put in place for Denial-of Service (DoS) attacks.'
  desc 'check', 'Review the container platform configuration to determine if users are uniquely identified and authenticated before the API is executed. 

If users are not uniquely identified or are not authenticated, this is a finding.'
  desc 'fix', 'Configure the container platform to uniquely identify and authenticate users before container platform API access.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36012r600715_chk'
  tag severity: 'medium'
  tag gid: 'V-233076'
  tag rid: 'SV-233076r600717_rule'
  tag stig_id: 'SRG-APP-000148-CTR-000340'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-35980r600716_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
