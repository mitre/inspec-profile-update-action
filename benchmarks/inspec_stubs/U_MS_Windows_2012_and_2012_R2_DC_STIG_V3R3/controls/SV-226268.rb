control 'SV-226268' do
  title 'Standard user accounts must only have Read permissions to the Winlogon registry key.'
  desc 'Permissions on the Winlogon registry key must only allow privileged accounts to change registry values.  If standard users have these permissions, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  desc 'check', 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Right-click on "WinLogon" and select "Permissions…".
Select "Advanced".

If the permissions are not as restrictive as the defaults listed below, this is a finding.

The following are the same for each permission listed:
Type - Allow
Inherited from - MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
Applies to - This key and subkeys

Columns: Principal - Access
TrustedInstaller - Full Control
SYSTEM - Full Control
Administrators - Full Control
Users - Read
ALL APPLICATION PACKAGES - Read'
  desc 'fix', 'Maintain permissions at least as restrictive as the defaults listed below for the "WinLogon" registry key.  It is recommended to not change the permissions from the defaults.

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

The following are the same for each permission listed:
Type - Allow
Inherited from - MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
Applies to - This key and subkeys

Columns: Principal - Access
TrustedInstaller - Full Control
SYSTEM - Full Control
Administrators - Full Control
Users - Read
ALL APPLICATION PACKAGES - Read'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27970r476648_chk'
  tag severity: 'high'
  tag gid: 'V-226268'
  tag rid: 'SV-226268r794557_rule'
  tag stig_id: 'WN12-RG-000001'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27958r476649_fix'
  tag 'documentable'
  tag legacy: ['SV-53123', 'V-26070']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
