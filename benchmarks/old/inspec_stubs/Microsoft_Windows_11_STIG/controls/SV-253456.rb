control 'SV-253456' do
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc 'Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously", both of which must be blank under other requirements.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56909r829450_chk'
  tag severity: 'high'
  tag gid: 'V-253456'
  tag rid: 'SV-253456r829452_rule'
  tag stig_id: 'WN11-SO-000165'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-56859r829451_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
