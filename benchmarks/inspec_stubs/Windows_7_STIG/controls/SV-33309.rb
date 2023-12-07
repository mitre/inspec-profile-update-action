control 'SV-33309' do
  title 'Standard user accounts must only have Read permissions to the Winlogon registry key.'
  desc 'Permissions on the Winlogon registry key must only allow privileged accounts to change registry values. If standard users have this capability there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  desc 'check', 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Right-click on "WinLogon" and select "Permissions…".
Select "Advanced".

If the permissions are not as restrictive as the defaults listed below, this is a finding.

The following are the same for each permission listed:
Type - Allow
Inherited from - MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
Apply to - This key and subkeys

Columns: Name - Permission
TrustedInstaller - Full Control
SYSTEM - Full Control
Administrators - Full Control
Users - Read'
  desc 'fix', 'Maintain permissions at least as restrictive as the defaults listed below for the "WinLogon" registry key.  It is recommended to not change the permissions from the defaults.

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

The following are the same for each permission listed:
Type - Allow
Inherited from - MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
Apply to - This key and subkeys

Columns: Name - Permission
TrustedInstaller - Full Control
SYSTEM - Full Control
Administrators - Full Control
Users - Read'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-74005r2_chk'
  tag severity: 'high'
  tag gid: 'V-26070'
  tag rid: 'SV-33309r3_rule'
  tag gtitle: 'Winlogon Registry Permissions'
  tag fix_id: 'F-80401r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
