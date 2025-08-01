control 'SV-42614' do
  title 'Standard user accounts must only have Read permissions to the Active Setup\\Installed Components registry key.'
  desc 'Permissions on the Active Setup\\Installed Components registry key must only allow privileged accounts to add or change registry values.  If standard user accounts have this capability there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  desc 'check', 'Navigate to the following registry key and review the assigned permissions:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components

On 64-bit systems also review the permissions assigned to the following registry key:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components 

Verify that standard user accounts and groups only have Read permissions to this registry key. If any standard user accounts or groups have greater permissions this is a finding. The default permissions satisfy this requirement.'
  desc 'fix', 'Ensure only Read permissions are assigned to standard user accounts and groups for the following registry keys.  The default configuration satisfies this requirement.
All systems
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components
64-bit systems
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-40783r2_chk'
  tag severity: 'high'
  tag gid: 'V-32282'
  tag rid: 'SV-42614r1_rule'
  tag stig_id: 'WINRG-000001'
  tag gtitle: 'WINRG-000001 Active Setup\\Installed Components Registry Permissions'
  tag fix_id: 'F-36207r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
