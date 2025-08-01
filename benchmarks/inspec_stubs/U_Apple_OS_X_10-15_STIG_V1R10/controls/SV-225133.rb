control 'SV-225133' do
  title 'The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Password policy is set with the Passcode Policy configuration profile.

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep 'maxFailedAttempts\|minutesUntilFailedLoginReset'

If "maxFailedAttempts" is not set to "3" and "minutesUntilFailedLoginReset" is not set to "15", this is a finding.)
  desc 'fix', 'This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26832r467567_chk'
  tag severity: 'medium'
  tag gid: 'V-225133'
  tag rid: 'SV-225133r853311_rule'
  tag stig_id: 'AOSX-15-000022'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-26820r467568_fix'
  tag 'documentable'
  tag legacy: ['SV-111643', 'V-102681']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
