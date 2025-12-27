control 'SV-253458' do
  title 'NTLM must be prevented from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

Value Name: allownullsessionfallback

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow LocalSystem NULL session fallback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56911r829456_chk'
  tag severity: 'medium'
  tag gid: 'V-253458'
  tag rid: 'SV-253458r829458_rule'
  tag stig_id: 'WN11-SO-000180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56861r829457_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
