control 'SV-254471' do
  title 'Windows Server 2022 must prevent NTLM from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

Value Name: allownullsessionfallback

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: Allow LocalSystem NULL session fallback to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57956r849227_chk'
  tag severity: 'medium'
  tag gid: 'V-254471'
  tag rid: 'SV-254471r849229_rule'
  tag stig_id: 'WN22-SO-000270'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57907r849228_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
