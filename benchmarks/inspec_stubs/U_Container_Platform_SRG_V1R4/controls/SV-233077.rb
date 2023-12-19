control 'SV-233077' do
  title 'The container platform must uniquely identify and authenticate processes acting on behalf of the users.'
  desc 'The container platform will instantiate a container image and use the user privileges given to the user used to execute the container. To ensure accountability and prevent unauthenticated access to containers, the user the container is using to execute must be uniquely identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', 'Review the container platform configuration to determine if processes acting on behalf of users are uniquely identified and authenticated. 

If processes acting on behalf of users are not uniquely identified or are not authenticated, this is a finding.'
  desc 'fix', 'Configure the container platform to uniquely identify and authenticate processes acting on behalf of users.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36013r600718_chk'
  tag severity: 'medium'
  tag gid: 'V-233077'
  tag rid: 'SV-233077r879589_rule'
  tag stig_id: 'SRG-APP-000148-CTR-000345'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-35981r600719_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
