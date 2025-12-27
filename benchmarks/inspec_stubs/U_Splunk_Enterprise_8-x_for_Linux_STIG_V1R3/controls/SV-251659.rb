control 'SV-251659' do
  title 'Splunk Enterprise must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication. The mitigation settings in this requirement apply in the event a local account is created.'
  desc 'check', 'This check is applicable to the instance with the Search Head role, which may be a different instance in a distributed environment.

Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the authentication.conf file.
 
If the authentication.conf file does not exist, this is a finding.

If the "lockoutAttempts" is missing or is configured to more than 3, this is a finding.

If the "lockoutThresholdMins" is missing or is configured to less than 15, this is a finding.'
  desc 'fix', 'If the authentication.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify the following lines in the authentication.conf file under the [splunk_auth]:

lockoutAttempts = 3
lockoutThresholdMins = 15'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55097r819080_chk'
  tag severity: 'medium'
  tag gid: 'V-251659'
  tag rid: 'SV-251659r819082_rule'
  tag stig_id: 'SPLK-CL-000060'
  tag gtitle: 'SRG-APP-000065-AU-000240'
  tag fix_id: 'F-55051r819081_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
