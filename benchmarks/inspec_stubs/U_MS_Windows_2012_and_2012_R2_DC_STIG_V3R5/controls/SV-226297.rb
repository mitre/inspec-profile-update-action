control 'SV-226297' do
  title 'The Windows SMB server must be configured to always perform SMB packet signing.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.  Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Digitally sign communications (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27999r476735_chk'
  tag severity: 'medium'
  tag gid: 'V-226297'
  tag rid: 'SV-226297r852141_rule'
  tag stig_id: 'WN12-SO-000032'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27987r476736_fix'
  tag 'documentable'
  tag legacy: ['SV-52936', 'V-6833']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
