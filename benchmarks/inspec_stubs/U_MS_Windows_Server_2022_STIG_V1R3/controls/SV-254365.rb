control 'SV-254365' do
  title 'Windows Server 2022 must not save passwords in the Remote Desktop Client.'
  desc 'Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DisablePasswordSaving

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Connection Client >> Do not allow passwords to be saved to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57850r848909_chk'
  tag severity: 'medium'
  tag gid: 'V-254365'
  tag rid: 'SV-254365r848911_rule'
  tag stig_id: 'WN22-CC-000340'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-57801r848910_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
