control 'SV-88325' do
  title 'The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft network server: Digitally sign communications (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73661'
  tag rid: 'SV-88325r1_rule'
  tag stig_id: 'WN16-SO-000230'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-80111r1_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
