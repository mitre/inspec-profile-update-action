control 'SV-254376' do
  title 'Windows Server 2022 must disable automatically signing in the last interactive user after a system-initiated restart.'
  desc 'Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Logon Options >> Sign-in and lock last interactive user automatically after a restart to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57861r848942_chk'
  tag severity: 'medium'
  tag gid: 'V-254376'
  tag rid: 'SV-254376r848944_rule'
  tag stig_id: 'WN22-CC-000450'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-57812r848943_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
