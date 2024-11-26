control 'SV-225118' do
  title 'The macOS system must be configured to prevent Apple Watch from terminating a session lock.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock"

allowAutoUnlock = 0;

If there is no result or "allowAutoUnlock" is not set to "0", this is a finding.'
  desc 'fix', 'This setting is enforced using the “Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26817r467522_chk'
  tag severity: 'medium'
  tag gid: 'V-225118'
  tag rid: 'SV-225118r610901_rule'
  tag stig_id: 'AOSX-15-000001'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-26805r467523_fix'
  tag 'documentable'
  tag legacy: ['V-102651', 'SV-111613']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
