control 'SV-252448' do
  title 'The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Password policy is set with the Passcode Policy configuration profile.

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep 'maxFailedAttempts\|minutesUntilFailedLoginReset'

If "maxFailedAttempts" is not set to "3" and "minutesUntilFailedLoginReset" is not set to "15", this is a finding.)
  desc 'fix', 'This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55904r816156_chk'
  tag severity: 'medium'
  tag gid: 'V-252448'
  tag rid: 'SV-252448r853260_rule'
  tag stig_id: 'APPL-12-000022'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-55854r816157_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
