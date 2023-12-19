control 'SV-102575' do
  title 'The Apache web server must perform server-side session management.'
  desc "Session management is the practice of protecting the bulk of the user authorization and identity information. Storing of this data can occur on the client system or on the server.

When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is stored in a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the hijacking of a session along with all of the user's credentials.

When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and web server will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised."
  desc 'check', %q(In a command line, navigate to <'INSTALL PATH'>\bin. Run "httpd -M" to view a list of installed modules.

If the module "mod_session" is not enabled, this is a finding.)
  desc 'fix', %q(Uncomment the "mod_session" module in the <'INSTALLED PATH'>\conf\httpd.conf file.

Additional documentation can be found at: 

https://httpd.apache.org/docs/2.4/mod/mod_usertrack.html

https://httpd.apache.org/docs/2.4/mod/mod_session.html)
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92487'
  tag rid: 'SV-102575r1_rule'
  tag stig_id: 'AS24-W2-000020'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-98729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
