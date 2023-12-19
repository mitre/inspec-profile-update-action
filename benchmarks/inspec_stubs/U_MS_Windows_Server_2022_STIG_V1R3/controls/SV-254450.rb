control 'SV-254450' do
  title 'Windows Server 2022 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Domain member: Digitally encrypt or sign secure channel data (always) to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57935r849164_chk'
  tag severity: 'medium'
  tag gid: 'V-254450'
  tag rid: 'SV-254450r849166_rule'
  tag stig_id: 'WN22-SO-000060'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-57886r849165_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
