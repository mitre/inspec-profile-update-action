control 'SV-222582' do
  title 'The application must not re-use or recycle session IDs.'
  desc 'Many web development frameworks such as PHP, .NET, and ASP include their own mechanisms for session management. Whenever possible it is recommended to utilize the provided session management framework.

Session identifiers are assigned to application users so they can be uniquely identified. This allows the user to customize their web application experience and also allows the developer to differentiate between users thereby providing the opportunity to customize the user’s features and functions.

Once a user has logged out of the application or had their session terminated, their session IDs should not be re-used. Session IDs should also not be used for other purposes such as creating unique file names and they should also not be re-assigned to other users once the original user has logged out or otherwise quit the application.

Allowing session ID reuse increases the risk of replay attacks.

Session testing is a detailed undertaking and is usually done in the course of a web application vulnerability or penetration assessment.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify how the application generates user session IDs.

Application session testing is required in order to verify this requirement.

Request the latest application vulnerability or penetration test results.

Verify the test configuration includes session handling vulnerability tests.

If the application is re-using/copying the users existing session ID that was created on one system in order to maintain user state when traversing multiple application servers in the same domain, this is not a finding.

If the session testing results indicate application session IDs are re-used after the user has logged out, this is a finding.'
  desc 'fix', 'Design the application to not re-use session IDs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24252r493654_chk'
  tag severity: 'medium'
  tag gid: 'V-222582'
  tag rid: 'SV-222582r508029_rule'
  tag stig_id: 'APSC-DV-002280'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-24241r493655_fix'
  tag 'documentable'
  tag legacy: ['V-70215', 'SV-84837']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
