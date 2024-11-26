control 'SV-16595' do
  title 'Windows Movie Maker Web Links'
  desc 'This check verifies that the links to web sites in Windows Movie Maker will not be available.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\WindowsMovieMaker\\

Value Name:	 Webhelp

Type:   REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Windows Movie Maker online Web links” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-15322r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15678'
  tag rid: 'SV-16595r1_rule'
  tag gtitle: 'Windows Movie Maker Web Links'
  tag fix_id: 'F-15545r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
