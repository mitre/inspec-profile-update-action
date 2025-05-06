control 'SV-33307' do
  title 'Standard user accounts must only have Read permissions to the Winlogon registry key.'
  desc 'Permissions on the Winlogon registry key must only allow privileged accounts to change registry values. If standard users have this capability there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  desc 'check', 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Review the permissions.

If the default permissions listed below have been changed, this is a finding.

Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Special
(Special = Full Control - Subkeys only)'
  desc 'fix', 'Maintain the default permissions of the following registry key:

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Special
(Special = Full Control - Subkeys only)'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-66317r1_chk'
  tag severity: 'high'
  tag gid: 'V-26070'
  tag rid: 'SV-33307r2_rule'
  tag gtitle: 'Winlogon Registry Permissions'
  tag fix_id: 'F-71705r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
