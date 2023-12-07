control 'SV-226074' do
  title 'Domain created Active Directory Organizational Unit (OU) objects must have proper access control permissions.'
  desc 'When directory service database objects do not have appropriate access control permissions, it may be possible for malicious users to create, read, update, or delete the objects and degrade or destroy the integrity of the data.  When the directory service is used for identification, authentication, or authorization functions, a compromise of the database objects could lead to a compromise of all systems that rely on the directory service.

For Active Directory (AD), the Organizational Unit (OU) objects require special attention.  In a distributed administration model (i.e., help desk), OU objects are more likely to have access permissions changed from the secure defaults.  If inappropriate access permissions are defined for OU objects, it could allow an intruder to add or delete users in the OU.  This could result in unauthorized access to data or a Denial of Service to authorized users.'
  desc 'check', 'Verifying the permissions on domain defined OUs.

Open "Active Directory Users and Computers".  (Available from various menus or run "dsa.msc".)
Ensure Advanced Features is selected in the View menu.

For each OU that is defined (folder in folder icon) excluding the Domain Controllers OU:
Right click the OU and select Properties.
Select the Security tab.

If the permissions on the OU are not at least as restrictive as those below, this is a finding.

The permissions shown are at the summary level.  More detailed permissions can be viewed by selecting the next Advanced button, selecting the desired Permission entry and the Edit button.

Self - Special permissions

Authenticated Users - Read, Special permissions
The Special permissions for Authenticated Users are Read type.  If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

SYSTEM - Full Control

Domain Admins - Full Control

Enterprise Admins - Full Control

Administrators - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions

Pre-Windows 2000 Compatible Access - Special permissions
The Special permissions for Pre-Windows 2000 Compatible Access are for Read types.  If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

If an ISSO-approved distributed administration model (help desk or other user support staff) is implemented, permissions above Read may be allowed for groups documented by the ISSO.'
  desc 'fix', 'Ensure the permissions on domain defined OUs are at least as restrictive as the defaults below.

Document any additional permissions above read with the ISSO if an approved distributed administration model (help desk or other user support staff) is implemented.

Self - Special permissions

Authenticated Users - Read, Special permissions
The Special permissions for Authenticated Users are Read type. If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

SYSTEM - Full Control

Domain Admins - Full Control

Enterprise Admins - Full Control

Administrators - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions

Pre-Windows 2000 Compatible Access - Special permissions
The Special permissions for Pre-Windows 2000 Compatible Access are for Read types. If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

Severity Override Guidance: If any OU with improper permissions includes identification or authentication data (e.g., accounts, passwords, or password hash data) used by systems to determine access control, the severity is CAT I (e.g., OUs that include user accounts, including service/application accounts).

If the OU with improper permissions does not include identification and authentication data used by systems to determine access control, the severity is CAT II (e.g., Workstation, Printer OUs).'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27776r475545_chk'
  tag severity: 'high'
  tag gid: 'V-226074'
  tag rid: 'SV-226074r852061_rule'
  tag stig_id: 'WN12-AD-000005-DC'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27764r794775_fix'
  tag 'documentable'
  tag legacy: ['SV-51179', 'V-39333']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
