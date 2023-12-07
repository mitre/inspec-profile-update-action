control 'SV-48292' do
  title 'Connections to non-domain networks when connected to a domain authenticated network must be blocked.'
  desc 'Multiple network connections can provide additional attack vectors to a system and should be limited.  When connected to a domain, communication must go through the domain connection.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fBlockNonDomain

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connection Manager -> "Prohibit connection to non-domain networks when connected to domain authenticated network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44970r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36675'
  tag rid: 'SV-48292r2_rule'
  tag stig_id: 'WN08-CC-000015'
  tag gtitle: 'WN08-CC-000015'
  tag fix_id: 'F-41427r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
