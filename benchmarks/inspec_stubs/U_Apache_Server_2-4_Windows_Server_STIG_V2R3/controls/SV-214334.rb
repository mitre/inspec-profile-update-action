control 'SV-214334' do
  title 'The Apache web server must generate unique session identifiers that cannot be reliably reproduced.'
  desc 'Communication between a client and the Apache web server is done using the HTTP protocol, but HTTP is a stateless protocol. To maintain a connection or session, a web server will generate a session identifier (ID) for each client session when the session is initiated. The session ID allows the Apache web server to track a user session and, in many cases, the user, if the user previously logged on to a hosted application.

Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of generated identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, the attacker will have more difficulty in hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

Check to see if the "mod_unique_id" is loaded.

If it does not exist, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALL PATH'>\conf\httpd.conf file and load the "mod_unique_id" module.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15546r277505_chk'
  tag severity: 'medium'
  tag gid: 'V-214334'
  tag rid: 'SV-214334r879639_rule'
  tag stig_id: 'AS24-W1-000500'
  tag gtitle: 'SRG-APP-000224-WSR-000136'
  tag fix_id: 'F-15544r277506_fix'
  tag 'documentable'
  tag legacy: ['SV-102501', 'V-92413']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
