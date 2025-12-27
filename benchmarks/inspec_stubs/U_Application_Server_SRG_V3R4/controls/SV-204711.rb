control 'SV-204711' do
  title 'The application server must ensure remote sessions for accessing security functions and security-relevant information are logged.'
  desc 'Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.

Remote access by administrators requires that the admin activity be logged.

Application servers provide a web and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.'
  desc 'check', 'Review the application server product documentation to determine if the application server logs remote administrative sessions.

If the application server does not log remote sessions for the admin user, then this is a finding.'
  desc 'fix', 'Configure the application server to log an event for each instance when the administrator accesses the system remotely.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4831r282780_chk'
  tag severity: 'medium'
  tag gid: 'V-204711'
  tag rid: 'SV-204711r879521_rule'
  tag stig_id: 'SRG-APP-000016-AS-000013'
  tag gtitle: 'SRG-APP-000016'
  tag fix_id: 'F-4831r282781_fix'
  tag 'documentable'
  tag legacy: ['SV-71683', 'V-57411']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
