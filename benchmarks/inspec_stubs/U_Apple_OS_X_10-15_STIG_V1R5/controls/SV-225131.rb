control 'SV-225131' do
  title 'The macOS system must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'The password policy is set with a configuration profile. Run the following command to check if the system has the correct setting for the number of permitted failed logon attempts:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxFailedAttempts

If the return is null, or not, “maxFailedAttempts = 3”, this is a finding.'
  desc 'fix', 'This setting is enforced using the “Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26830r467561_chk'
  tag severity: 'medium'
  tag gid: 'V-225131'
  tag rid: 'SV-225131r610901_rule'
  tag stig_id: 'AOSX-15-000020'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-26818r467562_fix'
  tag 'documentable'
  tag legacy: ['SV-111639', 'V-102677']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
