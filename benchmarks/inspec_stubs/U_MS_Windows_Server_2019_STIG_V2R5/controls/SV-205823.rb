control 'SV-205823' do
  title 'Windows Server 2019 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked. If this policy is enabled, outgoing secure channel traffic will be signed.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: SignSecureChannel

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally sign secure channel data (when possible)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6088r355831_chk'
  tag severity: 'medium'
  tag gid: 'V-205823'
  tag rid: 'SV-205823r852525_rule'
  tag stig_id: 'WN19-SO-000080'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-6088r355832_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag legacy: ['V-93551', 'SV-103637']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
