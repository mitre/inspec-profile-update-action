control 'SV-48236' do
  title 'The Responder network protocol driver must be disabled.'
  desc 'The Responder network protocol driver allows a computer to be discovered and located on a network.  Disabling this helps protect the system from potentially being discovered and connected to by unauthorized devices.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

Value Name: AllowRspndrOndomain
Value Name: AllowRspndrOnPublicNet
Value Name: EnableRspndr
Value Name: ProhibitRspndrOnPrivateNet

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Responder (RSPNDR) driver" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15697'
  tag rid: 'SV-48236r2_rule'
  tag stig_id: 'WN08-CC-000002'
  tag gtitle: 'Network – Responder Driver'
  tag fix_id: 'F-41372r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
