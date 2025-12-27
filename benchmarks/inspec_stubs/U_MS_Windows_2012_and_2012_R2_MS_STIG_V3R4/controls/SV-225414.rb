control 'SV-225414' do
  title 'Automatically signing in the last interactive user after a system-initiated restart must be disabled (Windows 2012 R2).'
  desc 'Windows 2012 R2 can be configured to automatically sign the user back in after a Windows Update restart.  Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.'
  desc 'check', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options -> "Sign-in last interactive user automatically after a system-initiated restart" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27113r471584_chk'
  tag severity: 'medium'
  tag gid: 'V-225414'
  tag rid: 'SV-225414r569185_rule'
  tag stig_id: 'WN12-CC-000145'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27101r471585_fix'
  tag 'documentable'
  tag legacy: ['SV-56355', 'V-43245']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
