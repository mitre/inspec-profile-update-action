control 'SV-214277' do
  title 'The Apache web server must perform server-side session management.'
  desc "Session management is the practice of protecting the bulk of the user authorization and identity information. This data can be stored on the client system or on the server. 
 
When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is stored in a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the possibility of the hijacking of a session along with all of the user's credentials. 
 
When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and Apache web server will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised."
  desc 'check', 'In a command line, run "httpd -M | grep -i session_module" and "httpd -M | grep -i usertrack_module". 
 
If "session_module" module and "usertrack_module" are not enabled or do not exist, this is a finding.'
  desc 'fix', 'If the modules are not installed, install any missing packages. 
 
Add the following lines to the "httpd.conf" file: 
 
LoadModule usertrack_module modules/mod_usertrack.so 
 
LoadModule session_module modules/mod_session.so 
 
Additional documentation can be found at: 
 
https://httpd.apache.org/docs/2.4/mod/mod_usertrack.html 
 
https://httpd.apache.org/docs/2.4/mod/mod_session.html 
 
Restart Apache: apachectl restart'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15490r277172_chk'
  tag severity: 'medium'
  tag gid: 'V-214277'
  tag rid: 'SV-214277r612241_rule'
  tag stig_id: 'AS24-U2-000020'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-15488r277173_fix'
  tag 'documentable'
  tag legacy: ['V-92761', 'SV-102849']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
