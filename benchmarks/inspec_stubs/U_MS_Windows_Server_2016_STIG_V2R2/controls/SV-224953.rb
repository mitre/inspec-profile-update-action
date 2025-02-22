control 'SV-224953' do
  title 'Users must be prevented from changing installation options.'
  desc 'Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Allow user control over installs" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26644r465761_chk'
  tag severity: 'medium'
  tag gid: 'V-224953'
  tag rid: 'SV-224953r569186_rule'
  tag stig_id: 'WN16-CC-000450'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-26632r465762_fix'
  tag 'documentable'
  tag legacy: ['SV-88247', 'V-73583']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
