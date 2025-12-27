control 'SV-214307' do
  title 'The Apache web server must perform server-side session management.'
  desc "Session management is the practice of protecting the bulk of the user authorization and identity information. Storing of this data can occur on the client system or on the server.

When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is stored in a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the possibility of the hijacking of a session along with all of the user's credentials.

When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and Apache web server will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised."
  desc 'check', %q(In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If "mod_session" module and "mod_usertrack" are not enabled, this is a finding.

session_module (shared)
usertrack_module (shared))
  desc 'fix', %q(Uncomment the "usertrack_module" module line and the "session_module" module in the <'INSTALL PATH'>\conf\httpd.conf file.

Restart the Apache service.

Additional documentation can be found at:

https://httpd.apache.org/docs/2.4/mod/mod_usertrack.html

https://httpd.apache.org/docs/2.4/mod/mod_session.html)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15519r277424_chk'
  tag severity: 'medium'
  tag gid: 'V-214307'
  tag rid: 'SV-214307r505936_rule'
  tag stig_id: 'AS24-W1-000020'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-15517r277425_fix'
  tag 'documentable'
  tag legacy: ['SV-102417', 'V-92329']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
