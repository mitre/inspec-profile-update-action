control 'SV-90793' do
  title 'The OS X system must not allow an unattended or automatic logon to the system.'
  desc 'When automatic logons are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer to log on. Disabling automatic logons mitigates this risk.'
  desc 'check', 'To check if the system is configured to automatically log on, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76105'
  tag rid: 'SV-90793r1_rule'
  tag stig_id: 'AOSX-12-000925'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-82743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
