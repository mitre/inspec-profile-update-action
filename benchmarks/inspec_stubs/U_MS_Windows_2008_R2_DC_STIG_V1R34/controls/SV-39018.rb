control 'SV-39018' do
  title 'File Replication Service (FRS) directory data files must have proper access control permissions.'
  desc 'Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data.'
  desc 'check', %q(If the system is using the more current Distributed File System (DFS) replication, this is NA.

Execute the command "Dfsrmig /getmigrationstate", to verify DFSR is being used.
The following message should be returned if the system is using DFSR:  "All Domain Controllers have migrated successfully to Global state ('Eliminated').  Migration has reached a consistent state on all Domain Controllers."

If the system is using FRS:
Run "Regedit".
 Navigate to "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NtFrs\Parameters".
Note the value for "Working Directory", typically "%SystemRoot%\ntfrs".
Verify the permissions of the noted location. 
If the access control permissions of the FRS directory are not at least as restrictive as those below, this is a finding.

FRS Directory Permissions:
Administrators - Full Control (F)
SYSTEM - Full Control (F))
  desc 'fix', 'If the system is using the more current DFS replication, this is NA.

Maintain the access control permissions for the FRS directory as outlined below.

FRS Directory Permissions:
Administrators - Full Control (F)
SYSTEM - Full Control (F)'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-49677r2_chk'
  tag severity: 'medium'
  tag gid: 'V-27109'
  tag rid: 'SV-39018r2_rule'
  tag stig_id: 'DS00.0121_2008_R2'
  tag gtitle: 'Directory Data - FRS Directory data files'
  tag fix_id: 'F-50025r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
