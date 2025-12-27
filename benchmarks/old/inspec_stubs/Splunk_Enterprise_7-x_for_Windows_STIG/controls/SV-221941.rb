control 'SV-221941' do
  title 'Splunk Enterprise must enforce the limit of 3 consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account gets created, for example, an emergency account of last resort for recovery.'
  desc 'check', 'Select Settings >> Access Controls >> Password Policy Management.

Verify that Lockout is Enabled, Failed login attempts is set to 3, and Lockout threshold in minutes is set to 15.

If these settings are not set as described, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Password Policy Management.

Set Lockout to Enabled. Set Failed login attempts to 3 and Lockout threshold in minutes to 15.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23655r420291_chk'
  tag severity: 'medium'
  tag gid: 'V-221941'
  tag rid: 'SV-221941r879546_rule'
  tag stig_id: 'SPLK-CL-000240'
  tag gtitle: 'SRG-APP-000065-AU-000240'
  tag fix_id: 'F-23644r420292_fix'
  tag 'documentable'
  tag legacy: ['SV-111331', 'V-102387']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
