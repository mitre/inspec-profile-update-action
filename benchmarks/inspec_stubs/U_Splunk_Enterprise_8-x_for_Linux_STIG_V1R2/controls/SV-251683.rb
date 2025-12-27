control 'SV-251683' do
  title 'Splunk Enterprise must be configured to enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account is created.'
  desc 'check', 'Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the authentication.conf file.
 
If the authentication.conf file does not exist, this is a finding.

If the "minPasswordDigit" is missing or is configured to 0, this is a finding.'
  desc 'fix', 'If the authentication.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify the following lines in the authentication.conf file under the [splunk_auth]:

minPasswordDigit = 1'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55121r819113_chk'
  tag severity: 'low'
  tag gid: 'V-251683'
  tag rid: 'SV-251683r819115_rule'
  tag stig_id: 'SPLK-CL-000360'
  tag gtitle: 'SRG-APP-000168-AU-002510'
  tag fix_id: 'F-55075r819114_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
