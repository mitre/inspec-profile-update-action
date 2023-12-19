control 'SV-254468' do
  title 'Windows Server 2022 must be configured to prevent anonymous users from having the same permissions as the Everyone group.'
  desc 'Access by anonymous users must be restricted. If this setting is enabled, anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network access: Let Everyone permissions apply to anonymous users to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57953r849218_chk'
  tag severity: 'medium'
  tag gid: 'V-254468'
  tag rid: 'SV-254468r849220_rule'
  tag stig_id: 'WN22-SO-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57904r849219_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
