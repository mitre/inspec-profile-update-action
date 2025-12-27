control 'SV-226136' do
  title 'The Responder network protocol driver must be disabled.'
  desc 'The Responder network protocol driver allows a computer to be discovered and located on a network.  Disabling this helps protect the system from potentially being discovered and connected to by unauthorized devices.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

Value Name: AllowRspndrOndomain
Value Name: AllowRspndrOnPublicNet
Value Name: EnableRspndr
Value Name: ProhibitRspndrOnPrivateNet

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Responder (RSPNDR) driver" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27838r475731_chk'
  tag severity: 'medium'
  tag gid: 'V-226136'
  tag rid: 'SV-226136r794412_rule'
  tag stig_id: 'WN12-CC-000002'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27826r475732_fix'
  tag 'documentable'
  tag legacy: ['V-15697', 'SV-53081']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
