control 'SV-30999' do
  title 'Update access to the directory schema must be restricted to appropriate accounts.'
  desc 'A failure to control update access to the AD Schema object could result in the creation of invalid directory objects and attributes. Applications that rely on AD could fail as a result of invalid formats and values. The presence of invalid directory objects and attributes could cause failures in Windows AD client functions and improper resource access decisions.'
  desc 'check', 'Start a Schema management console. (See supplemental notes.)
Select, then right-click on the Active Directory Schema entry in the left pane.
Select Permissions.

If any of the permissions for the Schema object are not at least as restrictive as those below, this is a finding. 

The permissions shown are at the summary level.  More detailed permissions can be viewed by selecting the Advanced button, selecting the desired entry, and the Edit button.

Authenticated Users:
Read
Special Permissions
The Special permissions for Authenticated Users are List and Read type.  If detailed permissions include any additional Permissions or Properties this is a finding.

System:
Full Control

Enterprise Read-only Domain Controllers:
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set

Schema Admins:
Read
Write
Create all child objects
Change schema master
Manage replication topology
Monitor active directory replication
Read only replication secret synchronization
Reanimate tombstones
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set
Replication synchronization
Update schema cache
Special permissions
(Special permissions = all except Full, Delete, and Delete subtree when detailed permissions viewed.)

Administrators:
Manage replication topology
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set
Replication Synchronization

Enterprise Domain Controllers:
Manage replication topology
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set
Replication Synchronization

Supplemental Notes:
If the Schema management console has not already been configured on the computer, create a console by using the following:

The steps for adding the snap-in may vary depending on the Windows version.
Register the required DLL module by typing the following at a command line "regsvr32 schmmgmt.dll".
Run "mmc.exe" to start a Microsoft Management Console. 
Select Add/Remove Snap-in from the File menu.
From the Available Standalone Snap-ins list, select Active Directory Schema
Select the Add button.
Select the OK button.

When done using the console, select Exit from the File (or Console) menu.
Select the No button to the Save console settings… prompt (unless the SA wishes to retain this console). If the console is retained, the recommended name is schmmgmt.msc and the recommended location is the [systemroot]\\system32 directory.'
  desc 'fix', 'Ensure the access control permissions for the AD Schema object conform to the required permissions as shown below.

Authenticated Users:
Read
Special Permissions
The Special permissions for Authenticated Users are List and Read type.  If detailed permissions include any additional Permissions or Properties this is a finding.

System:
Full Control

Enterprise Read-only Domain Controllers:
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set

Schema Admins:
Read
Write
Create all child objects
Change schema master
Manage replication topology
Monitor active directory replication
Read only replication secret synchronization
Reanimate tombstones
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set
Replication synchronization
Update schema cache
Special permissions
(Special permissions = all except Full, Delete, and Delete subtree when detailed permissions viewed.)

Administrators:
Manage replication topology
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set
Replication Synchronization

Enterprise Domain Controllers:
Manage replication topology
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes In Filtered Set
Replication Synchronization'
  impact 0.7
  ref 'DPMS Target Active Directory Forest'
  tag check_id: 'C-66419r3_chk'
  tag severity: 'high'
  tag gid: 'V-15372'
  tag rid: 'SV-30999r4_rule'
  tag stig_id: 'DS00.3140_AD'
  tag gtitle: 'Directory Schema Update Access'
  tag fix_id: 'F-71807r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
