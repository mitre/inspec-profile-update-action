control 'SV-222579' do
  title 'Applications must use system-generated session identifiers that protect against session fixation.'
  desc 'Session fixation allows an attacker to hijack a valid user’s application session. The attack focuses on the manner in which a web application manages the user’s session ID. Applications become vulnerable when they do not assign a new session ID when authenticating users thereby using the existing session ID.

Many web development frameworks such as PHP, .NET, and ASP include their own mechanisms for session management. Whenever possible it is recommended to utilize the provided session management framework.

In many cases, creating a new session ID cookie containing a new unique value whenever authentication is performed will address the issue of session fixation.

Allowing the user to submit a session ID also introduces the risk that the application could be subject to a session fixation attack.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify how the application generates user session IDs.

Application session testing is required in order to verify this requirement.

Request the latest application vulnerability or penetration test results.

Verify the test configuration includes session handling vulnerability tests.

If the application is re-using/copying the users existing session ID that was created on one system in order to maintain user state when traversing multiple application servers in the same domain, this is not a finding.

If the session testing results indicate application session IDs are re-used after the user has logged out, this is a finding.'
  desc 'fix', 'Design the application to generate new session IDs with unique values when authenticating user sessions.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24249r493645_chk'
  tag severity: 'medium'
  tag gid: 'V-222579'
  tag rid: 'SV-222579r508029_rule'
  tag stig_id: 'APSC-DV-002250'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-24238r493646_fix'
  tag 'documentable'
  tag legacy: ['V-70209', 'SV-84831']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
