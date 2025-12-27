control 'SV-226325' do
  title 'NTLM must be prevented from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

Value Name: allownullsessionfallback

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow LocalSystem NULL session fallback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28027r476819_chk'
  tag severity: 'medium'
  tag gid: 'V-226325'
  tag rid: 'SV-226325r794603_rule'
  tag stig_id: 'WN12-SO-000062'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28015r476820_fix'
  tag 'documentable'
  tag legacy: ['SV-53177', 'V-21952']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
