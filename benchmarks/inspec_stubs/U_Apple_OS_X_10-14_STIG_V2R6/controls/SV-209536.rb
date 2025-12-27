control 'SV-209536' do
  title 'The macOS system must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'The password policy is set with a configuration profile. Run the following command to check if the system has the correct setting for the number of permitted failed logon attempts:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxFailedAttempts

If the return is null, or not, “maxFailedAttempts = 3”, this is a finding.'
  desc 'fix', 'This setting is enforced using the “Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9787r282090_chk'
  tag severity: 'medium'
  tag gid: 'V-209536'
  tag rid: 'SV-209536r610285_rule'
  tag stig_id: 'AOSX-14-000020'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-9787r282091_fix'
  tag 'documentable'
  tag legacy: ['SV-104951', 'V-95813']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
