control 'SV-253443' do
  title 'The system must be configured to require a strong session key.'
  desc 'A computer connecting to a domain controller will establish a secure channel. Requiring strong session keys enforces 128-bit encryption between systems.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
Warning: This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56896r829411_chk'
  tag severity: 'medium'
  tag gid: 'V-253443'
  tag rid: 'SV-253443r829413_rule'
  tag stig_id: 'WN11-SO-000060'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-56846r829412_fix'
  tag 'documentable'
  tag cci: ['CCI-002388']
  tag nist: ['SC-5 (3) (a)']
end
