control 'SV-224963' do
  title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc 'Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Disallow WinRM from storing RunAs credentials" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26654r465791_chk'
  tag severity: 'medium'
  tag gid: 'V-224963'
  tag rid: 'SV-224963r852338_rule'
  tag stig_id: 'WN16-CC-000550'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-26642r465792_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00156']
  tag 'documentable'
  tag legacy: ['SV-88267', 'V-73603']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
