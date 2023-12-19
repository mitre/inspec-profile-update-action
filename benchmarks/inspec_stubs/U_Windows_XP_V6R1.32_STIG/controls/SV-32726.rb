control 'SV-32726' do
  title 'Standard user accounts will only have Read permissions to the Winlogon registry key.'
  desc 'Permissions on the Winlogon registry key should only allow privileged accounts to change registry values. If standard users have this capability there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  desc 'check', 'Navigate to the following registry key:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon.
Verify the permissions assigned.

Standard user accounts and groups will only have Read permissions to this registry key.  If any standard user accounts or groups have greater permissions, this is a finding.  The default permissions satisfy this requirement.'
  desc 'fix', 'Assign only Read permissions for standard user accounts and groups to the HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon registry key.  This is the default configuration.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32949r1_chk'
  tag severity: 'high'
  tag gid: 'V-26070'
  tag rid: 'SV-32726r1_rule'
  tag gtitle: 'Winlogon Registry Permissions'
  tag fix_id: 'F-29102r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
