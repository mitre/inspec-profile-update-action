control 'SV-226071' do
  title 'The Active Directory SYSVOL directory must have the proper access control permissions.'
  desc 'Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data.

The SYSVOL directory contains public files (to the domain) such as policies and logon scripts.  Data in shared subdirectories are replicated to all domain controllers in a domain.'
  desc 'check', 'Verify the permissions on the SYSVOL directory.

Open a command prompt.
Run "net share".
Make note of the directory location of the SYSVOL share.  

By default this will be \\Windows\\SYSVOL\\sysvol.  For this requirement, permissions will be verified at the first SYSVOL directory level.

Alternately, use Icacls.exe to view the permissions of the SYSVOL directory.
Open a command prompt.
Run "icacls c:\\Windows\\SYSVOL
The following results should be displayed:

NT AUTHORITY\\Authenticated Users:(RX)
NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(GR,GE)
BUILTIN\\Server Operators:(RX)
BUILTIN\\Server Operators:(OI)(CI)(IO)(GR,GE)
BUILTIN\\Administrators:(M,WDAC,WO)
BUILTIN\\Administrators:(OI)(CI)(IO)(F)
NT AUTHORITY\\SYSTEM:(F)
NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\\Administrators:(M,WDAC,WO)
CREATOR OWNER:(OI)(CI)(IO)(F)

(RX) - Read & execute 
Run "icacls /help" to view definitions of other permission codes.

If the above results are not displayed, this is a finding.'
  desc 'fix', 'Ensure the permissions on SYSVOL directory do not allow greater than read & execute for standard user accounts or groups.  The defaults below meet this requirement.

Type - Allow 
Principal - Authenticated Users
Access - Read & execute
Inherited from - None
Applies to - This folder, subfolder and files

Type - Allow 
Principal - Server Operators
Access - Read & execute
Inherited from - None
Applies to - This folder, subfolder and files

Type - Allow 
Principal - Administrators
Access - Special
Inherited from - None
Applies to - This folder only
(Access - Special - Basic Permissions: all selected except Full control)

Type - Allow 
Principal - CREATOR OWNER
Access - Full control
Inherited from - None
Applies to - Subfolders and files only

Type - Allow 
Principal - Administrators
Access - Full control
Inherited from - None
Applies to - Subfolders and files only

Type - Allow 
Principal - SYSTEM
Access - Full control
Inherited from - None
Applies to - This folder, subfolders and files'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27773r642135_chk'
  tag severity: 'high'
  tag gid: 'V-226071'
  tag rid: 'SV-226071r569184_rule'
  tag stig_id: 'WN12-AD-000002-DC'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27761r475537_fix'
  tag 'documentable'
  tag legacy: ['SV-51176', 'V-39331']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
