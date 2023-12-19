control 'SV-225447' do
  title 'Anonymous access to the registry must be restricted.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require anonymous access to the registry.  This must be limited to properly protect the system.'
  desc 'check', 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\

If the key does not exist, this is a finding.

Right-click on "winreg" and select "Permissions…".
Select "Advanced".

If the permissions are not as restrictive as the defaults listed below, this is a finding.

The following are the same for each permission listed:
Type - Allow
Inherited from - None

Columns: Principal - Access - Applies to
Administrators - Full Control - This key and subkeys
Backup Operators - Read - This key only
LOCAL SERVICE - Read - This key and subkeys'
  desc 'fix', 'Maintain permissions at least as restrictive as the defaults listed below for the "winreg" registry key.  It is recommended to not change the permissions from the defaults.

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\

The following are the same for each permission listed:
Type - Allow
Inherited from - None

Columns: Principal - Access - Applies to
Administrators - Full Control - This key and subkeys
Backup Operators - Read - This key only
LOCAL SERVICE - Read - This key and subkeys'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27146r471683_chk'
  tag severity: 'high'
  tag gid: 'V-225447'
  tag rid: 'SV-225447r569185_rule'
  tag stig_id: 'WN12-RG-000004'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27134r471684_fix'
  tag 'documentable'
  tag legacy: ['SV-52864', 'V-1152']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
