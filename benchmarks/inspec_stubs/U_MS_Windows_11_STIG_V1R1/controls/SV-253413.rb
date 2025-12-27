control 'SV-253413' do
  title 'Automatically signing in the last interactive user after a system-initiated restart must be disabled.'
  desc 'Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Logon Options >> "Sign-in last interactive user automatically after a system-initiated restart" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56866r829321_chk'
  tag severity: 'medium'
  tag gid: 'V-253413'
  tag rid: 'SV-253413r829323_rule'
  tag stig_id: 'WN11-CC-000325'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-56816r829322_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
