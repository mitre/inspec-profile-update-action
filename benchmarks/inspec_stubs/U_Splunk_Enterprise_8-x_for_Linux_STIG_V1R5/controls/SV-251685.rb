control 'SV-251685' do
  title 'Splunk Enterprise must be configured to enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account is created.'
  desc 'check', 'Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the authentication.conf file.
 
If the authentication.conf file does not exist, this is a finding.

If the "minPasswordSpecial" is missing or is configured to 0, this is a finding.'
  desc 'fix', 'If the authentication.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify the following lines in the authentication.conf file under the [splunk_auth]:

minPasswordSpecial = 1'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55123r819119_chk'
  tag severity: 'low'
  tag gid: 'V-251685'
  tag rid: 'SV-251685r879606_rule'
  tag stig_id: 'SPLK-CL-000380'
  tag gtitle: 'SRG-APP-000169-AU-002520'
  tag fix_id: 'F-55077r819120_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
