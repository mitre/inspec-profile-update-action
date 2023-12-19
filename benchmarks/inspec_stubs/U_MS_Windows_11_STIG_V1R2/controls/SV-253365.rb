control 'SV-253365' do
  title 'Connections to non-domain networks when connected to a domain authenticated network must be blocked.'
  desc 'Multiple network connections can provide additional attack vectors to a system and must be limited. When connected to a domain, communication must go through the domain connection.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fBlockNonDomain

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows Connection Manager >> "Prohibit connection to non-domain networks when connected to domain authenticated network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56818r829177_chk'
  tag severity: 'medium'
  tag gid: 'V-253365'
  tag rid: 'SV-253365r829179_rule'
  tag stig_id: 'WN11-CC-000060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56768r829178_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
