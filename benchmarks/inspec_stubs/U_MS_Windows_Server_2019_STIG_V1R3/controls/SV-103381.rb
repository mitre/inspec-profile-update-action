control 'SV-103381' do
  title 'Windows Server 2019 must be configured to prevent anonymous users from having the same permissions as the Everyone group.'
  desc 'Access by anonymous users must be restricted. If this setting is enabled, anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Let Everyone permissions apply to anonymous users" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92611r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93293'
  tag rid: 'SV-103381r1_rule'
  tag stig_id: 'WN19-SO-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-99539r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
