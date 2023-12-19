control 'SV-225314' do
  title 'The Mapper I/O network protocol (LLTDIO) driver must be disabled.'
  desc 'The Mapper I/O network protocol (LLTDIO) driver allows the discovery of the connected network and allows various options to be enabled.  Disabling this helps protect the system from potentially discovering and connecting to unauthorized devices.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

Value Name: AllowLLTDIOOndomain
Value Name: AllowLLTDIOOnPublicNet
Value Name: EnableLLTDIO
Value Name: ProhibitLLTDIOOnPrivateNet

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Mapper I/O (LLTDIO) driver" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27013r471284_chk'
  tag severity: 'medium'
  tag gid: 'V-225314'
  tag rid: 'SV-225314r569185_rule'
  tag stig_id: 'WN12-CC-000001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27001r471285_fix'
  tag 'documentable'
  tag legacy: ['SV-53072', 'V-15696']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
