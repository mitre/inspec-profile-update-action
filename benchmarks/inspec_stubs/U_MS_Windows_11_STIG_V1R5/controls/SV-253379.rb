control 'SV-253379' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Enumerate local users on domain-joined computers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56832r829219_chk'
  tag severity: 'medium'
  tag gid: 'V-253379'
  tag rid: 'SV-253379r829221_rule'
  tag stig_id: 'WN11-CC-000130'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56782r829220_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
