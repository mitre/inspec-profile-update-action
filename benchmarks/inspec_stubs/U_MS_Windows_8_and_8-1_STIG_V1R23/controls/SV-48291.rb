control 'SV-48291' do
  title 'Simultaneous connections to the Internet or a Windows domain must be limited.'
  desc 'Multiple network connections can provide additional attack vectors to a system and must be limited.  The "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems from automatically establishing multiple connections.  When both wired and wireless connections are available, for example, the less preferred connection (typically wireless) will be disconnected.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fMinimizeConnections

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows Connection Manager >> "Minimize the number of simultaneous connections to the Internet or a Windows Domain" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36674'
  tag rid: 'SV-48291r3_rule'
  tag stig_id: 'WN08-CC-000014'
  tag gtitle: 'WN08-CC-000014'
  tag fix_id: 'F-41426r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
