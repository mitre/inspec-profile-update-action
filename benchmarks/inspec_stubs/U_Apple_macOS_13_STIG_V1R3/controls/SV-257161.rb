control 'SV-257161' do
  title 'The macOS system must be configured to disable password forwarding for FileVault.'
  desc 'When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.'
  desc 'check', 'Verify the macOS system is configured to disable password forwarding with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "DisableFDEAutoLogin"

DisableFDEAutoLogin = 1;

If "DisableFDEAutoLogin" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable password forwarding by installing the "Smart Card Policy" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the "Smart Card Policy".'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60846r905114_chk'
  tag severity: 'medium'
  tag gid: 'V-257161'
  tag rid: 'SV-257161r905116_rule'
  tag stig_id: 'APPL-13-000033'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60787r905115_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
