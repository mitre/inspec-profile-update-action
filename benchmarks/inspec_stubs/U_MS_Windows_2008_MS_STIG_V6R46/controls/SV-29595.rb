control 'SV-29595' do
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
Inherited from - <not inherited>

Columns: Name - Permission - Apply to
Administrators - Full Control - This key and subkeys
Backup Operators - Special - This key only
(Special = Query Value, Enumerate Subkeys, Notify, Read Control (effectively = Read))
LOCAL SERVICE - Read - This key and subkeys'
  desc 'fix', 'Maintain permissions at least as restrictive as the defaults listed below for the "winreg" registry key.  It is recommended to not change the permissions from the defaults.

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\

The following are the same for each permission listed:
Type - Allow
Inherited from - <not inherited>

Columns: Name - Permission - Apply to
Administrators - Full Control - This key and subkeys
Backup Operators - Special - This key only
(Special = Query Value, Enumerate Subkeys, Notify, Read Control (effectively = Read))
LOCAL SERVICE - Read - This key and subkeys'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-74019r2_chk'
  tag severity: 'high'
  tag gid: 'V-1152'
  tag rid: 'SV-29595r3_rule'
  tag gtitle: 'Anonymous Access to the Registry'
  tag fix_id: 'F-80415r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
