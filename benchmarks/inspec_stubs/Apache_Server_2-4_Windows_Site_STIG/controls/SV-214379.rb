control 'SV-214379' do
  title 'The Apache web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.'
  desc 'Generating a session identifier (ID) that is not easily guessed through brute force is essential to deter several types of session attacks. By knowing the session ID, an attacker can hijack a user session that has already been user authenticated by the hosted application. The attacker does not need to guess user identifiers and passwords or have a secure token since the user session has already been authenticated.

By generating session IDs that contain as much of the character set as possible, i.e., A-Z, a-z, and 0-9, the session ID becomes exponentially harder to guess.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Check to see if the "mod_unique_id" is loaded.

If it does not exist, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and load the "mod_unique_id" module.

Restart Apache.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15590r277878_chk'
  tag severity: 'medium'
  tag gid: 'V-214379'
  tag rid: 'SV-214379r397735_rule'
  tag stig_id: 'AS24-W2-000520'
  tag gtitle: 'SRG-APP-000224-WSR-000138'
  tag fix_id: 'F-15588r277879_fix'
  tag 'documentable'
  tag legacy: ['SV-102631', 'V-92543']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
