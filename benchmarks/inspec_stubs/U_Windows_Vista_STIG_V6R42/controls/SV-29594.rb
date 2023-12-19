control 'SV-29594' do
  title 'Anonymous access to the registry must be restricted.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require anonymous access to the registry.  This must be limited to properly protect the system.'
  desc 'check', 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\

If the key does not exist, this is a finding.

Review the permissions.

If the default permissions listed below have been changed, this is a finding.

Administrators - Full Control
Backup Operators - Special
(Special = Query Value, Enumerate Subkeys, Notify, Read Control (effectively = Read) - This key only)
LOCAL SERVICE - Read'
  desc 'fix', 'Maintain the default permissions of the following registry key:

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\

Administrators - Full
Backup Operators - Special
(Special = Query Value, Enumerate Subkeys, Notify, Read Control (effectively = Read) - This key only)
LOCAL SERVICE - Read'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-66315r1_chk'
  tag severity: 'high'
  tag gid: 'V-1152'
  tag rid: 'SV-29594r2_rule'
  tag gtitle: 'Anonymous Access to the Registry'
  tag fix_id: 'F-71703r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
