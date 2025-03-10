control 'SV-225199' do
  title 'The macOS system must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'To check if the system is configured to automatically log on, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26898r467765_chk'
  tag severity: 'medium'
  tag gid: 'V-225199'
  tag rid: 'SV-225199r877377_rule'
  tag stig_id: 'AOSX-15-002066'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-26886r467766_fix'
  tag 'documentable'
  tag legacy: ['V-102817', 'SV-111779']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
