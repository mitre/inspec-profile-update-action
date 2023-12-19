control 'SV-251684' do
  title 'Splunk Enterprise must be configured to enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account is created.'
  desc 'check', 'Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the authentication.conf file.
 
If the authentication.conf file does not exist, this is a finding.

If the "minPasswordLength" is missing or is configured to 14 or less, this is a finding.'
  desc 'fix', 'If the authentication.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify the following lines in the authentication.conf file under the [splunk_auth]:

minPasswordLength = 15 or more'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55122r819116_chk'
  tag severity: 'low'
  tag gid: 'V-251684'
  tag rid: 'SV-251684r879601_rule'
  tag stig_id: 'SPLK-CL-000370'
  tag gtitle: 'SRG-APP-000164-AU-002480'
  tag fix_id: 'F-55076r819117_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
