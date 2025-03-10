control 'SV-209608' do
  title 'The macOS system must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'To check if the system is configured to automatically log on, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9859r282306_chk'
  tag severity: 'medium'
  tag gid: 'V-209608'
  tag rid: 'SV-209608r610285_rule'
  tag stig_id: 'AOSX-14-002066'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-9859r282307_fix'
  tag 'documentable'
  tag legacy: ['SV-105091', 'V-95953']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
