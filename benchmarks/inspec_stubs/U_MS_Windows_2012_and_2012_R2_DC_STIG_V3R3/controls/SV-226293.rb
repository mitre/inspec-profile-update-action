control 'SV-226293' do
  title 'The Windows SMB client must be configured to always perform SMB packet signing.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.  Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network client: Digitally sign communications (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27995r476723_chk'
  tag severity: 'medium'
  tag gid: 'V-226293'
  tag rid: 'SV-226293r794570_rule'
  tag stig_id: 'WN12-SO-000028'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27983r476724_fix'
  tag 'documentable'
  tag legacy: ['SV-52935', 'V-6832']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
