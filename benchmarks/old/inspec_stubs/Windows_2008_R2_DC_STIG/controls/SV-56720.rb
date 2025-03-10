control 'SV-56720' do
  title 'Domain created Active Directory Organizational Unit (OU) objects must have proper access control permissions.'
  desc 'When Active Directory (AD) objects do not have appropriate access control permissions, it may be possible for malicious users to create, read, update, or delete the objects and degrade or destroy the integrity of the data.  When the directory service is used for identification, authentication, or authorization functions, a compromise of the database objects could lead to a compromise of all systems that rely on the directory service.

AD Organizational Unit (OU) objects require special attention.  In a distributed administration model (i.e., help desk), OU objects are more likely to have access permissions changed from the secure defaults.  Inappropriate access permissions defined for OU objects could allow an intruder or unauthorized personnel to add or delete accounts in the OU.  This could result in unauthorized access to data or a Denial of Service to authorized users.'
  desc 'check', 'Verify the permissions on domain defined OUs.

Open "Active Directory Users and Computers". (Available from various menus or run "dsa.msc".)
Select Advanced Features in the View menu if not previously selected.

For each OU that is defined (folder in folder icon), excluding the Domain Controllers OU:
Right click the OU and select Properties.
Select the Security tab.

If the permissions on the OU are not at least as restrictive as those below, this is a finding.

The permissions shown are at the summary level.  More detailed permissions can be viewed by selecting the Advanced button, selecting the desired Permission entry and the Edit button.

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

If an IAO-approved distributed administration model (help desk or other user support staff) is implemented, permissions above Read may be allowed for groups documented with the IAO.'
  desc 'fix', 'Maintain the permissions on domain defined OUs to be at least as restrictive as the defaults below.

Document any additional permissions above read with the IAO if an approved distributed administration model (help desk or other user support staff) is implemented.

Self - Special permissions

Authenticated Users - Read, Special permissions
The Special permissions for Authenticated Users are Read type. If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

SYSTEM - Full Control

Domain Admins - Full Control

Enterprise Admins - Full Control

Administrators - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions

Pre-Windows 2000 Compatible Access - Special permissions
The Special permissions for Pre-Windows 2000 Compatible Access are for Read types. If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-49416r3_chk'
  tag severity: 'high'
  tag gid: 'V-39333'
  tag rid: 'SV-56720r1_rule'
  tag stig_id: 'WINAD-000005-DC_2008_R2'
  tag gtitle: 'WINAD-000005-DC'
  tag fix_id: 'F-49487r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If any OU with improper permissions includes identification or authentication data (e.g., accounts, passwords, or password hash data) used by systems to determine access control, the severity is Category I (e.g., OUs that include user accounts, including service/application accounts).

If the OU with improper permissions does not include identification and authentication data used by systems to determine access control, the severity is Category II (e.g., Workstation, Printer OUs).'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
