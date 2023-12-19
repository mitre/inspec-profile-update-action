control 'SV-254430' do
  title 'Windows Server 2022 local users on domain-joined member servers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'This applies to member servers. For domain controllers and standalone or nondomain-joined systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> Enumerate local users on domain-joined computers to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57915r849104_chk'
  tag severity: 'medium'
  tag gid: 'V-254430'
  tag rid: 'SV-254430r849106_rule'
  tag stig_id: 'WN22-MS-000030'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57866r849105_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
