control 'SV-226294' do
  title 'The Windows SMB client must be enabled to perform SMB packet signing when possible.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.   If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27996r476726_chk'
  tag severity: 'medium'
  tag gid: 'V-226294'
  tag rid: 'SV-226294r569184_rule'
  tag stig_id: 'WN12-SO-000029'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27984r476727_fix'
  tag 'documentable'
  tag legacy: ['SV-52874', 'V-1166']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
