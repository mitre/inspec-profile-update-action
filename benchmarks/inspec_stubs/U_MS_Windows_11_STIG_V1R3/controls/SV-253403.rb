control 'SV-253403' do
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.'
  desc 'Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisableCdm

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection >> "Do not allow drive redirection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56856r829291_chk'
  tag severity: 'medium'
  tag gid: 'V-253403'
  tag rid: 'SV-253403r829293_rule'
  tag stig_id: 'WN11-CC-000275'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-56806r829292_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
