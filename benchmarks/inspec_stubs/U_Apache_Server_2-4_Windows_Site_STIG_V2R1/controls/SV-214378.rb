control 'SV-214378' do
  title 'The Apache web server must generate unique session identifiers that cannot be reliably reproduced.'
  desc 'Communication between a client and the web server is done using the HTTP protocol, but HTTP is a stateless protocol. To maintain a connection or session, a web server will generate a session identifier (ID) for each client session when the session is initiated. The session ID allows the web server to track a user session and, in many cases, the user, if the user previously logged on to a hosted application.

By being able to guess session IDs, an attacker can easily perform a man-in-the-middle attack. To truly generate random session identifiers that cannot be reproduced, the web server session ID generator, when used twice with the same input criteria, must generate an unrelated random ID.

The session ID generator also needs to be a FIPS 140-2 approved generator.

'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "mod_unique_id" is loaded.

If it does not exist, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and load the "mod_unique_id" module.

Restart Apache.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15589r277875_chk'
  tag severity: 'medium'
  tag gid: 'V-214378'
  tag rid: 'SV-214378r397735_rule'
  tag stig_id: 'AS24-W2-000500'
  tag gtitle: 'SRG-APP-000224-WSR-000136'
  tag fix_id: 'F-15587r277876_fix'
  tag satisfies: ['SRG-APP-000224-WSR-000136', 'SRG-APP-000224-WSR-000137']
  tag 'documentable'
  tag legacy: ['SV-102627', 'V-92539']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
