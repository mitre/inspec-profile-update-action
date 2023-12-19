control 'SV-252515' do
  title 'The macOS system must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'To check if the system is configured to automatically log on, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55971r816357_chk'
  tag severity: 'medium'
  tag gid: 'V-252515'
  tag rid: 'SV-252515r877377_rule'
  tag stig_id: 'APPL-12-002066'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-55921r816358_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
