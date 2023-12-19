control 'SV-225445' do
  title 'Standard user accounts must only have Read permissions to the Active Setup\\Installed Components registry key.'
  desc 'Permissions on the Active Setup\\Installed Components registry key must only allow privileged accounts to add or change registry values.  If standard user accounts have these permissions, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  desc 'check', 'Run "Regedit".
Navigate to the following registry keys and review the permissions:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\ (64-bit systems)

If the default permissions listed below have been changed, this is a finding.

Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Full Control (Subkeys only)
ALL APPLICATION PACKAGES - Read'
  desc 'fix', 'Maintain the default permissions of the following registry keys:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\ (64-bit systems only)
 
Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Full Control (Subkeys only)
ALL APPLICATION PACKAGES - Read'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27144r471677_chk'
  tag severity: 'high'
  tag gid: 'V-225445'
  tag rid: 'SV-225445r852243_rule'
  tag stig_id: 'WN12-RG-000002'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27132r471678_fix'
  tag 'documentable'
  tag legacy: ['SV-52956', 'V-32282']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
