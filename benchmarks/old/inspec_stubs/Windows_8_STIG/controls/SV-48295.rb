control 'SV-48295' do
  title 'Standard user accounts must only have Read permissions to the Active Setup\\Installed Components registry key.'
  desc 'Permissions on the Active Setup\\Installed Components registry key must only allow privileged accounts to add or change registry values. If standard user accounts have this capability, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
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
  desc 'fix', 'Maintain the default permissions of the following registry keys as noted below:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\ (64-bit systems only)

Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Full Control (Subkeys only)
ALL APPLICATION PACKAGES - Read'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-64139r1_chk'
  tag severity: 'high'
  tag gid: 'V-32282'
  tag rid: 'SV-48295r2_rule'
  tag stig_id: 'WN08-RG-000002'
  tag gtitle: 'WINRG-000001 Active Setup\\Installed Components Registry Permissions'
  tag fix_id: 'F-69319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
