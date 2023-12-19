control 'SV-225132' do
  title 'The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.'
  desc 'Setting a lockout time period of 15 minutes is an effective deterrent against brute forcing that also makes allowances for legitimate mistakes by users. When three invalid logon attempts are made, the account will be locked.'
  desc 'check', 'Password policy is set with the Passcode Policy configuration profile.

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minutesUntilFailedLoginReset

If the return is null or not “minutesUntilFailedLoginReset = 15”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile or by a directory service.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26831r467564_chk'
  tag severity: 'medium'
  tag gid: 'V-225132'
  tag rid: 'SV-225132r853310_rule'
  tag stig_id: 'AOSX-15-000021'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-26819r467565_fix'
  tag 'documentable'
  tag legacy: ['SV-111641', 'V-102679']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
