control 'SV-55998' do
  title 'Automatically signing in the last interactive user after a system-initiated restart must be disabled.'
  desc 'Windows can be configured to automatically sign the user back in after a Windows Update restart.  Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Logon Options >> "Sign-in last interactive user automatically after a system-initiated restart" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43245'
  tag rid: 'SV-55998r3_rule'
  tag stig_id: 'WN08-CC-000145'
  tag gtitle: 'WINCC-000145'
  tag fix_id: 'F-71665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
