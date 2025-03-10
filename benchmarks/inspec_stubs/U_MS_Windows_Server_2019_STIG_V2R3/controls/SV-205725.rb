control 'SV-205725' do
  title 'Windows Server 2019 must restrict anonymous access to Named Pipes and Shares.'
  desc 'Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously", both of which must be blank under other requirements.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5990r355093_chk'
  tag severity: 'high'
  tag gid: 'V-205725'
  tag rid: 'SV-205725r569188_rule'
  tag stig_id: 'WN19-SO-000250'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-5990r355094_fix'
  tag 'documentable'
  tag legacy: ['V-93539', 'SV-103625']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
