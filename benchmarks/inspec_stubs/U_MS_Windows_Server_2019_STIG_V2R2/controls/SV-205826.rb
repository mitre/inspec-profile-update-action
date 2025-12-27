control 'SV-205826' do
  title 'Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations. If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-6091r355840_chk'
  tag severity: 'medium'
  tag gid: 'V-205826'
  tag rid: 'SV-205826r569188_rule'
  tag stig_id: 'WN19-SO-000170'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-6091r355841_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag legacy: ['V-93557', 'SV-103643']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
