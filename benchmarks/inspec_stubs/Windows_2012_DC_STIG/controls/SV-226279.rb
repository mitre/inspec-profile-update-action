control 'SV-226279' do
  title 'Outgoing secure channel traffic must be encrypted or signed.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Digitally encrypt or sign secure channel data (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27981r476681_chk'
  tag severity: 'medium'
  tag gid: 'V-226279'
  tag rid: 'SV-226279r852134_rule'
  tag stig_id: 'WN12-SO-000012'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27969r476682_fix'
  tag 'documentable'
  tag legacy: ['SV-52934', 'V-6831']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
