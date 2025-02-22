control 'SV-222389' do
  title 'The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.'
  desc "Leaving a user’s application session established for an indefinite period of time increases the risk of session hijacking.

Session termination terminates an individual user's logical application session after 15 minutes of application inactivity at which time the user must re-authenticate and a new session must be established if the user desires to continue work in the application."
  desc 'check', 'Ask the application representative to demonstrate the configuration setting where the idle time out value is defined.

Alternatively, logon with a regular application user account and let the session sit idle for 15 minutes.

Attempt to access the application after 15 minutes of inactivity.

If the configuration setting is not set to time out user sessions after 15 minutes of inactivity, or if the regular user session used for testing does not time out after 15 minutes of inactivity, this is a finding.'
  desc 'fix', 'Design and configure the application to terminate the non-privileged users session after 15 minutes of inactivity.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24059r493075_chk'
  tag severity: 'medium'
  tag gid: 'V-222389'
  tag rid: 'SV-222389r508029_rule'
  tag stig_id: 'APSC-DV-000070'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-24048r493076_fix'
  tag 'documentable'
  tag legacy: ['V-69243', 'SV-83865']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
