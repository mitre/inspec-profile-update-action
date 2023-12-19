control 'SV-32423' do
  title 'The Responder network protocol driver will be disabled.'
  desc 'This check verifies that the Responder network protocol driver is disabled.'
  desc 'check', 'If the following registry values don’t exist or are not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

Value Name:  AllowRspndrOndomain
Value Name:  AllowRspndrOnPublicNet
Value Name:  EnableRspndr
Value Name:  ProhibitRspndrOnPrivateNet

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery “Turn on Responder (RSPNDR) driver” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-15385r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15697'
  tag rid: 'SV-32423r1_rule'
  tag gtitle: 'Network – Responder Driver'
  tag fix_id: 'F-15589r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
