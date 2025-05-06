control 'SV-257154' do
  title 'The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify the macOS system is configured to enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "maxFailedAttempts\\|minutesUntilFailedLoginReset"

maxFailedAttempts = 3;
minutesUntilFailedLoginReset = 15;

If "maxFailedAttempts" is not set to "3" and "minutesUntilFailedLoginReset" is not set to "15", this is a finding.'
  desc 'fix', 'Configure the macOS system to enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked by installing the "Passcode Policy" configuration profile or by a directory service.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60839r905093_chk'
  tag severity: 'medium'
  tag gid: 'V-257154'
  tag rid: 'SV-257154r905095_rule'
  tag stig_id: 'APPL-13-000022'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-60780r905094_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
