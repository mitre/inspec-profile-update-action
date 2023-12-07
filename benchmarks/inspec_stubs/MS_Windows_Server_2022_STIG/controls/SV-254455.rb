control 'SV-254455' do
  title 'Windows Server 2022 must be configured to require a strong session key.'
  desc 'A computer connecting to a domain controller will establish a secure channel. The secure channel connection may be subject to compromise, such as hijacking or eavesdropping, if strong session keys are not used to establish the connection. Requiring strong session keys enforces 128-bit encryption between systems.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 0x00000001 (1)
 
This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Domain member: Require strong (Windows 2000 or Later) session key to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57940r849179_chk'
  tag severity: 'medium'
  tag gid: 'V-254455'
  tag rid: 'SV-254455r849181_rule'
  tag stig_id: 'WN22-SO-000110'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-57891r849180_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
