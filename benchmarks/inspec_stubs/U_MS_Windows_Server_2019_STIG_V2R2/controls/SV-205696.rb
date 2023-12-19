control 'SV-205696' do
  title 'Windows Server 2019 local users on domain-joined member servers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'This applies to member servers. For domain controllers and standalone systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Enumerate local users on domain-joined computers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-5961r355006_chk'
  tag severity: 'medium'
  tag gid: 'V-205696'
  tag rid: 'SV-205696r569188_rule'
  tag stig_id: 'WN19-MS-000030'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-5961r355007_fix'
  tag 'documentable'
  tag legacy: ['SV-103505', 'V-93419']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
