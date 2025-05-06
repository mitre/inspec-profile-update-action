control 'SV-48235' do
  title 'The Mapper I/O network protocol (LLTDIO) driver must be disabled.'
  desc 'The Mapper I/O network protocol (LLTDIO) driver allows the discovery of the connected network and allows various options to be enabled.  Disabling this helps protect the system from potentially discovering and connecting to unauthorized devices.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

Value Name: AllowLLTDIOOndomain
Value Name: AllowLLTDIOOnPublicNet
Value Name: EnableLLTDIO
Value Name: ProhibitLLTDIOOnPrivateNet

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Mapper I/O (LLTDIO) driver" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44914r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15696'
  tag rid: 'SV-48235r2_rule'
  tag stig_id: 'WN08-CC-000001'
  tag gtitle: 'Network – Mapper I/O Driver'
  tag fix_id: 'F-41371r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
