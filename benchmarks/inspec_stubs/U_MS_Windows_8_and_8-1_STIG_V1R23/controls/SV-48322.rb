control 'SV-48322' do
  title 'The use of biometrics must be disabled.'
  desc 'Allowing biometrics may bypass required authentication methods.  Biometrics may only be used as an additional authentication factor where an enhanced strength of identity credential is necessary or desirable.  Additional factors must be met per DoD policy.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\

Value Name: Enabled

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Biometrics -> "Allow the use of biometrics" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44994r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36698'
  tag rid: 'SV-48322r2_rule'
  tag stig_id: 'WN08-CC-000075'
  tag gtitle: 'WINCC-000075'
  tag fix_id: 'F-41454r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
