control 'SV-225401' do
  title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc 'Storage of administrative credentials could allow unauthorized access.  Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Disallow WinRM from storing RunAs credentials" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27100r471545_chk'
  tag severity: 'medium'
  tag gid: 'V-225401'
  tag rid: 'SV-225401r569185_rule'
  tag stig_id: 'WN12-CC-000128'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-27088r471546_fix'
  tag 'documentable'
  tag legacy: ['SV-51757', 'V-36720']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
