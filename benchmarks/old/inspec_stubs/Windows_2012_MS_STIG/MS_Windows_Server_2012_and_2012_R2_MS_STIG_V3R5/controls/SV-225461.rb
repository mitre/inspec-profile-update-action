control 'SV-225461' do
  title 'The system must be configured to require a strong session key.'
  desc 'A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys enforces 128-bit encryption between systems.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27160r471725_chk'
  tag severity: 'medium'
  tag gid: 'V-225461'
  tag rid: 'SV-225461r852248_rule'
  tag stig_id: 'WN12-SO-000017'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27148r471726_fix'
  tag 'documentable'
  tag legacy: ['SV-52888', 'V-3374']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
