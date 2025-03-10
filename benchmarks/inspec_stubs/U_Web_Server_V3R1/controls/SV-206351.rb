control 'SV-206351' do
  title 'The web server must perform server-side session management.'
  desc "Session management is the practice of protecting the bulk of the user authorization and identity information. Storing of this data can occur on the client system or on the server. 

When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is stored in either a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the hijacking of a session along with all of the user's credentials.

When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and web server will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised."
  desc 'check', 'Review the web server documentation and configuration to determine if server-side session management is configured.

If it is not configured, this is a finding.'
  desc 'fix', 'Configure the web server to perform server-side session management.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6612r377645_chk'
  tag severity: 'medium'
  tag gid: 'V-206351'
  tag rid: 'SV-206351r395442_rule'
  tag stig_id: 'SRG-APP-000001-WSR-000002'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-6612r377646_fix'
  tag 'documentable'
  tag legacy: ['SV-53023', 'V-40792']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
