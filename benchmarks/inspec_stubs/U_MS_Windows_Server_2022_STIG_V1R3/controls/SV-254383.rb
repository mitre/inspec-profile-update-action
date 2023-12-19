control 'SV-254383' do
  title 'Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc 'Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> Disallow WinRM from storing RunAs credentials to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57868r848963_chk'
  tag severity: 'medium'
  tag gid: 'V-254383'
  tag rid: 'SV-254383r848965_rule'
  tag stig_id: 'WN22-CC-000520'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-57819r848964_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
