control 'SV-206402' do
  title 'The web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.'
  desc 'Generating a session identifier (ID) that is not easily guessed through brute force is essential to deter several types of session attacks. By knowing the session ID, an attacker can hijack a user session that has already been user-authenticated by the hosted application. The attacker does not need to guess user identifiers and passwords or have a secure token since the user session has already been authenticated.

By generating session IDs that contain as much of the character set as possible, i.e., A-Z, a-z, and 0-9, the session ID becomes exponentially harder to guess.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine what characters are used in generating session IDs.

If the web server is not configured to use at least A-Z, a-z, and 0-9 to generate session identifiers, this is a finding.'
  desc 'fix', 'Configure the web server to use at least A-Z, a-z, and 0-9 to generate session IDs.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6663r377798_chk'
  tag severity: 'medium'
  tag gid: 'V-206402'
  tag rid: 'SV-206402r397735_rule'
  tag stig_id: 'SRG-APP-000224-WSR-000138'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-6663r377799_fix'
  tag 'documentable'
  tag legacy: ['SV-54386', 'V-41809']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
