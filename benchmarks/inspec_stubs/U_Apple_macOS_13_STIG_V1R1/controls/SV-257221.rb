control 'SV-257221' do
  title 'The macOS system must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the macOS system is configured to not allow automatic logon with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "DisableAutoLoginClient"

"com.apple.login.mcx.DisableAutoLoginClient" = 1;

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to not allow automatic login by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60906r905294_chk'
  tag severity: 'medium'
  tag gid: 'V-257221'
  tag rid: 'SV-257221r905296_rule'
  tag stig_id: 'APPL-13-002066'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-60847r905295_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
