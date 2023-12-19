control 'SV-254464' do
  title 'Windows Server 2022 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Microsoft network server: Digitally sign communications (if client agrees) to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57949r849206_chk'
  tag severity: 'medium'
  tag gid: 'V-254464'
  tag rid: 'SV-254464r849208_rule'
  tag stig_id: 'WN22-SO-000200'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-57900r849207_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
