control 'SV-252455' do
  title 'The macOS system must be configured to disable password forwarding for FileVault2.'
  desc 'When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.'
  desc 'check', 'Verify that password forwarding has been disabled on the system:

# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "DisableFDEAutoLogin"

DisableFDEAutologin = 1;

If "DisableFDEAutologin" is not set to a value of "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Smart Card" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55911r816177_chk'
  tag severity: 'medium'
  tag gid: 'V-252455'
  tag rid: 'SV-252455r816179_rule'
  tag stig_id: 'APPL-12-000033'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55861r816178_fix'
  tag 'documentable'
  tag cci: ['CCI-002143']
  tag nist: ['AC-2 (11)']
end
