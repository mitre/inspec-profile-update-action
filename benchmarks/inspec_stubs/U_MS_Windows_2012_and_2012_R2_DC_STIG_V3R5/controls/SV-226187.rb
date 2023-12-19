control 'SV-226187' do
  title 'The use of biometrics must be disabled.'
  desc 'Allowing biometrics may bypass required authentication methods.  Biometrics may only be used as an additional authentication factor where an enhanced strength of identity credential is necessary or desirable.  Additional factors must be met per DoD policy.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\

Value Name: Enabled

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Biometrics -> "Allow the use of biometrics" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27889r475884_chk'
  tag severity: 'medium'
  tag gid: 'V-226187'
  tag rid: 'SV-226187r794439_rule'
  tag stig_id: 'WN12-CC-000075'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27877r475885_fix'
  tag 'documentable'
  tag legacy: ['SV-51739', 'V-36698']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
