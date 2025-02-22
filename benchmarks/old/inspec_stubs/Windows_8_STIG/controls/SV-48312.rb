control 'SV-48312' do
  title 'Signing in using a PIN must be turned off.'
  desc 'Strong sign-on must be used to protect a system.  The PIN feature is limited to 4 numbers and caches the domain password in the system vault.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\System\\

Value Name: AllowDomainPINLogon

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Turn on PIN sign-in" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44986r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36689'
  tag rid: 'SV-48312r2_rule'
  tag stig_id: 'WN08-CC-000053'
  tag gtitle: 'WN08-CC-000053'
  tag fix_id: 'F-41445r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
