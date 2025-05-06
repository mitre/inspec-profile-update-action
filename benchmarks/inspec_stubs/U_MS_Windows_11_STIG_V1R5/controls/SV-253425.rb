control 'SV-253425' do
  title 'Windows 11 must be configured to prevent users from receiving suggestions for third-party or additional applications.'
  desc 'Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\\

Value Name: DisableThirdPartySuggestions

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for User Configuration >> Administrative Templates. >> Windows Components >> Cloud Content >> "Do not suggest third-party content in Windows spotlight" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56878r829357_chk'
  tag severity: 'low'
  tag gid: 'V-253425'
  tag rid: 'SV-253425r829359_rule'
  tag stig_id: 'WN11-CC-000390'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56828r829358_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
