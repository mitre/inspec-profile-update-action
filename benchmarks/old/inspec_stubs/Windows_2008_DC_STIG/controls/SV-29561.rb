control 'SV-29561' do
  title 'Network – Mapper I/O Driver'
  desc 'This check verifies that the Mapper I/O network protocol driver is disabled.'
  desc 'check', 'If the following registry values don’t exist or are not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

Value Name:  AllowLLTDIOOndomain
Value Name:  AllowLLTDIOOnPublicNet
Value Name:  EnableLLTDIO
Value Name:  ProhibitLLTDIOOnPrivateNet

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery “Turn on Mapper I/O (LLTDIO) driver” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15384r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15696'
  tag rid: 'SV-29561r1_rule'
  tag gtitle: 'Network – Mapper I/O Driver'
  tag fix_id: 'F-15588r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
