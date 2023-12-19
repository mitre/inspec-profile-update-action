control 'SV-224956' do
  title 'Automatically signing in the last interactive user after a system-initiated restart must be disabled.'
  desc 'Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Logon Options >> "Sign-in last interactive user automatically after a system-initiated restart" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26647r465770_chk'
  tag severity: 'medium'
  tag gid: 'V-224956'
  tag rid: 'SV-224956r569186_rule'
  tag stig_id: 'WN16-CC-000480'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-26635r465771_fix'
  tag 'documentable'
  tag legacy: ['SV-88253', 'V-73589']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
