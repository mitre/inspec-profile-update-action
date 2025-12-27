control 'SV-225047' do
  title 'Windows Server 2016 must be configured to prevent anonymous users from having the same permissions as the Everyone group.'
  desc 'Access by anonymous users must be restricted. If this setting is enabled, anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Let everyone permissions apply to anonymous users" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26738r466043_chk'
  tag severity: 'medium'
  tag gid: 'V-225047'
  tag rid: 'SV-225047r569186_rule'
  tag stig_id: 'WN16-SO-000290'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26726r466044_fix'
  tag 'documentable'
  tag legacy: ['SV-88337', 'V-73673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
