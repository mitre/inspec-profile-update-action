control 'SV-253451' do
  title 'The Windows SMB server must be configured to always perform SMB packet signing.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft network server: Digitally sign communications (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56904r829435_chk'
  tag severity: 'medium'
  tag gid: 'V-253451'
  tag rid: 'SV-253451r829437_rule'
  tag stig_id: 'WN11-SO-000120'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-56854r829436_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
