control 'SV-251660' do
  title 'Splunk Enterprise must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the authentication.conf file.
 
If the authentication.conf file does not exist, this is a finding.

If the lockoutUsers" is missing or is configured to 0 or False, this is a finding.'
  desc 'fix', 'If the authentication.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify the following lines in the authentication.conf file under the [splunk_auth]:

lockoutUsers = True or 1'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55098r819083_chk'
  tag severity: 'medium'
  tag gid: 'V-251660'
  tag rid: 'SV-251660r879722_rule'
  tag stig_id: 'SPLK-CL-000070'
  tag gtitle: 'SRG-APP-000345-AU-000400'
  tag fix_id: 'F-55052r819084_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
