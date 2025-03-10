control 'SV-233071' do
  title 'The container platform must be configured with only essential configurations.'
  desc 'The container platform can be built with components that are not used for the intended purpose of the organization. To limit the attack surface of the container platform, it is essential that the non-essential services are not installed.'
  desc 'check', 'Review the container platform configuration and verify that only those components needed for operation are installed. 

If components are installed that are not used for the intended purpose of the organization, this is a finding.'
  desc 'fix', 'Identify the role the container platform is intended to play in the production environment and remove any components that are not needed or used for the intended purpose.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36007r600700_chk'
  tag severity: 'medium'
  tag gid: 'V-233071'
  tag rid: 'SV-233071r879587_rule'
  tag stig_id: 'SRG-APP-000141-CTR-000315'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-35975r600701_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
