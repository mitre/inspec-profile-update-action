control 'SV-214894' do
  title 'The macOS system must not allow an unattended or automatic logon to the system.'
  desc 'When automatic logons are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer to log on. Disabling automatic logons mitigates this risk.'
  desc 'check', 'To check if the system is configured to automatically log on, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16094r397254_chk'
  tag severity: 'medium'
  tag gid: 'V-214894'
  tag rid: 'SV-214894r609363_rule'
  tag stig_id: 'AOSX-13-000925'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16092r397255_fix'
  tag 'documentable'
  tag legacy: ['SV-96381', 'V-81667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
