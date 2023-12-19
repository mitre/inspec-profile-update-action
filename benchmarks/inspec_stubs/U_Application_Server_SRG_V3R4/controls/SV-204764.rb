control 'SV-204764' do
  title 'The application server must generate a unique session identifier for each session.'
  desc 'Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of session identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

Application servers must generate a unique session identifier for each application session so as to prevent session hijacking.'
  desc 'check', 'Review the application server session management configuration settings in either the application server management console, application server initialization or application server configuration files to determine if the application server is configured to generate a unique session identifier for each session.

If the application server is  not configured to generate a unique session identifier for each session, this is a finding.'
  desc 'fix', 'Configure the application server to generate a unique session identifier for each session.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4884r282939_chk'
  tag severity: 'medium'
  tag gid: 'V-204764'
  tag rid: 'SV-204764r879638_rule'
  tag stig_id: 'SRG-APP-000223-AS-000150'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-4884r282940_fix'
  tag 'documentable'
  tag legacy: ['V-57549', 'SV-71825']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
