control 'SV-204743' do
  title 'The application server must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server can disable non-essential features and capabilities.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to use only essential features and capabilities.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4863r282876_chk'
  tag severity: 'medium'
  tag gid: 'V-204743'
  tag rid: 'SV-204743r508029_rule'
  tag stig_id: 'SRG-APP-000141-AS-000095'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-4863r282877_fix'
  tag 'documentable'
  tag legacy: ['V-35234', 'SV-46521']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
