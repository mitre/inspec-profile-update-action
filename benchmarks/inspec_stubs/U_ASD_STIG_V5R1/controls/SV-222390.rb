control 'SV-222390' do
  title 'The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.'
  desc "Leaving an admin user's application session established for an indefinite period of time increases the risk of session hijacking.

Session termination terminates an individual user's logical application session after 10 minutes of application inactivity at which time the user must re-authenticate and a new session must be established if the user desires to continue work in the application."
  desc 'check', 'Ask the application representative to demonstrate the application configuration setting where the idle time out value is defined for admin users.

Alternatively, logon with an admin user account and let the session sit idle for 10 minutes.

Attempt to access the application after 10 minutes of inactivity.

If the configuration setting is not set to time out admin user sessions after 10 minutes of inactivity, or if the session used for testing does not time out after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Design and configure the application to terminate the admin users session after 10 minutes of inactivity.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24060r493078_chk'
  tag severity: 'medium'
  tag gid: 'V-222390'
  tag rid: 'SV-222390r508029_rule'
  tag stig_id: 'APSC-DV-000080'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-24049r493079_fix'
  tag 'documentable'
  tag legacy: ['V-69245', 'SV-83867']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
