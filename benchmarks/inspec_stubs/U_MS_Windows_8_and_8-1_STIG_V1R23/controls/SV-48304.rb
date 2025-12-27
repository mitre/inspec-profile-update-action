control 'SV-48304' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system.  Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Enumerate local users on domain-joined computers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44982r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36684'
  tag rid: 'SV-48304r3_rule'
  tag stig_id: 'WN08-CC-000051'
  tag gtitle: 'WINCC-000051'
  tag fix_id: 'F-41439r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
