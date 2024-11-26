control 'SV-226298' do
  title 'The Windows SMB server must perform SMB packet signing when possible.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.   Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Digitally sign communications (if client agrees)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28000r476738_chk'
  tag severity: 'medium'
  tag gid: 'V-226298'
  tag rid: 'SV-226298r569184_rule'
  tag stig_id: 'WN12-SO-000033'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27988r476739_fix'
  tag 'documentable'
  tag legacy: ['SV-52870', 'V-1162']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
