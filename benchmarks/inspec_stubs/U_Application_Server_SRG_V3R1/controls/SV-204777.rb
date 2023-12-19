control 'SV-204777' do
  title 'The application server must automatically terminate a user session after organization-defined conditions or trigger events requiring a session disconnect.'
  desc "An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use."
  desc 'check', 'Review application server documentation and configuration settings to determine if the application server is configured to close user sessions after defined conditions or trigger events are met.

If the application server is not configured or cannot be configured to disconnect users after defined conditions and trigger events are met, this is a finding.'
  desc 'fix', 'Configure the application server to terminate user sessions on defined conditions or trigger events.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4897r282978_chk'
  tag severity: 'medium'
  tag gid: 'V-204777'
  tag rid: 'SV-204777r508029_rule'
  tag stig_id: 'SRG-APP-000295-AS-000263'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-4897r282979_fix'
  tag 'documentable'
  tag legacy: ['SV-71673', 'V-57401']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
