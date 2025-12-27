control 'SV-226170' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system.  Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Enumerate local users on domain-joined computers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27872r475833_chk'
  tag severity: 'medium'
  tag gid: 'V-226170'
  tag rid: 'SV-226170r569184_rule'
  tag stig_id: 'WN12-CC-000051'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27860r475834_fix'
  tag 'documentable'
  tag legacy: ['V-36684', 'SV-51611']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
