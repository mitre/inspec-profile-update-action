control 'SV-226322' do
  title 'Network shares that can be accessed anonymously must not be allowed.'
  desc 'Anonymous access to network shares provides the potential for gaining unauthorized system access by network users.  This could lead to the exposure or corruption of sensitive data.'
  desc 'check', 'If the following registry value does not exist, this is not a finding:

If the following registry value does exist and is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: NullSessionShares

Value Type: REG_MULTI_SZ
Value: (Blank)'
  desc 'fix', 'Ensure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Shares that can be accessed anonymously" contains no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28024r476810_chk'
  tag severity: 'high'
  tag gid: 'V-226322'
  tag rid: 'SV-226322r794549_rule'
  tag stig_id: 'WN12-SO-000059'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-28012r476811_fix'
  tag 'documentable'
  tag legacy: ['SV-52884', 'V-3340']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
