control 'SV-204766' do
  title 'The application server must generate a unique session identifier using a FIPS 140-2 approved random number generator.'
  desc 'The application server will use session IDs to communicate between modules or applications within the application server and between the application server and users.  The session ID allows the application to track the communications along with credentials that may have been used to authenticate users or modules.

Unique session IDs are the opposite of sequentially generated session IDs which can be easily guessed by an attacker.  Unique session identifiers help to reduce predictability of said identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session.  If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', 'Review the application server configuration and documentation to determine if the application server uses a FIPS 140-2 approved random number generator to create unique session identifiers.

Have a user log onto the application server to determine if the session IDs generated are random and unique.

If the application server does not generate unique session identifiers and does not use a FIPS 140-2 random number generator to create the randomness of the session ID, this is a finding.'
  desc 'fix', 'Configure the application server to generate unique session identifiers and to use a FIPS 140-2 random number generator to generate the randomness of the session identifiers.'
  impact 0.7
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4886r282945_chk'
  tag severity: 'high'
  tag gid: 'V-204766'
  tag rid: 'SV-204766r879639_rule'
  tag stig_id: 'SRG-APP-000224-AS-000152'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-4886r282946_fix'
  tag 'documentable'
  tag legacy: ['SV-46709', 'V-35422']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
