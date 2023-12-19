control 'SV-225009' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'This applies to member servers. For domain controllers and standalone systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Enumerate local users on domain-joined computers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26700r465929_chk'
  tag severity: 'medium'
  tag gid: 'V-225009'
  tag rid: 'SV-225009r569186_rule'
  tag stig_id: 'WN16-MS-000030'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26688r465930_fix'
  tag 'documentable'
  tag legacy: ['V-73533', 'SV-88187']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
