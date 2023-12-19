control 'SV-225030' do
  title 'The setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: SealSecureChannel

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally encrypt secure channel data (when possible)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26721r465992_chk'
  tag severity: 'medium'
  tag gid: 'V-225030'
  tag rid: 'SV-225030r852379_rule'
  tag stig_id: 'WN16-SO-000090'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-26709r465993_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag legacy: ['SV-88299', 'V-73635']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
