control 'SV-205740' do
  title 'Windows Server 2019 Active Directory SYSVOL directory must have the proper access control permissions.'
  desc 'Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data.

The SYSVOL directory contains public files (to the domain) such as policies and logon scripts. Data in shared subdirectories are replicated to all domain controllers in a domain.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Open a command prompt.

Run "net share".

Make note of the directory location of the SYSVOL share.

By default, this will be \\Windows\\SYSVOL\\sysvol. For this requirement, permissions will be verified at the first SYSVOL directory level.

If any standard user accounts or groups have greater than "Read & execute" permissions, this is a finding. 

The default permissions noted below meet this requirement:

Open "Command Prompt".

Run "icacls c:\\Windows\\SYSVOL".

The following results should be displayed:

NT AUTHORITY\\Authenticated Users:(RX)
NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(GR,GE)
BUILTIN\\Server Operators:(RX)
BUILTIN\\Server Operators:(OI)(CI)(IO)(GR,GE)
BUILTIN\\Administrators:(M,WDAC,WO)
BUILTIN\\Administrators:(OI)(CI)(IO)(F)
NT AUTHORITY\\SYSTEM:(F)
NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
CREATOR OWNER:(OI)(CI)(IO)(F)

(RX) - Read & execute 

Run "icacls /help" to view definitions of other permission codes.'
  desc 'fix', 'Maintain the permissions on the SYSVOL directory. Do not allow greater than "Read & execute" permissions for standard user accounts or groups. The defaults below meet this requirement:

C:\\Windows\\SYSVOL
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

Authenticated Users - Read & execute - This folder, subfolder, and files
Server Operators - Read & execute- This folder, subfolder, and files
Administrators - Special - This folder only (Special = Basic Permissions: all selected except Full control)
CREATOR OWNER - Full control - Subfolders and files only
Administrators - Full control - Subfolders and files only
SYSTEM - Full control - This folder, subfolders, and files'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6005r852440_chk'
  tag severity: 'high'
  tag gid: 'V-205740'
  tag rid: 'SV-205740r877392_rule'
  tag stig_id: 'WN19-DC-000080'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-6005r355139_fix'
  tag 'documentable'
  tag legacy: ['V-93031', 'SV-103119']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
