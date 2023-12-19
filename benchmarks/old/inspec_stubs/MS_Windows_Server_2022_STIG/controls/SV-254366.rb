control 'SV-254366' do
  title 'Windows Server 2022 Remote Desktop Services must prevent drive redirection.'
  desc 'Preventing users from sharing the local drives on their client computers with Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisableCdm

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection >> Do not allow drive redirection to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57851r848912_chk'
  tag severity: 'medium'
  tag gid: 'V-254366'
  tag rid: 'SV-254366r848914_rule'
  tag stig_id: 'WN22-CC-000350'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-57802r848913_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
