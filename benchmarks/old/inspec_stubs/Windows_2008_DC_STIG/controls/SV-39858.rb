control 'SV-39858' do
  title 'The Active Directory SYSVOL directory must have the proper access control permissions.'
  desc 'Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data.

The SYSVOL directory contains public files (to the domain) such as policies and logon scripts.  Data in shared subdirectories are replicated to all domain controllers in a domain.'
  desc 'check', 'Verify the permissions on the SYSVOL directory.

Open a command prompt.
Run "net share".
Make note of the directory location of the SYSVOL share. 

By default this will be \\Windows\\SYSVOL\\sysvol.  For this requirement, permissions will be verified at the first SYSVOL directory level.

Open Windows Explorer.
Navigate to \\Windows\\SYSVOL (or the directory noted previously if different).
Right click the directory and select properties.
Select the Security tab.
Click Advanced.

If any standard user accounts or groups are allowed greater than read & execute permissions, this is a finding. The default permissions noted below meet this requirement.  

Name - Authenticated Users
Permission - Read & execute
Apply To - This folder, subfolder and files

Name - Server Operators
Permission - Read & execute
Apply To - This folder, subfolder and files

Name - Administrators
Permission - Special
Apply To - This folder only
(Permission - Special : all selected except Full control, Delete subfolders and files)

Name - CREATOR OWNER
Permission - Special (Full control in Detail view)
Apply To - Subfolders and files only

Name - Administrators
Permission - Special (Full control in Detail view)
Apply To - Subfolders and files only

Name - SYSTEM
Permission - Full control
Apply To - This folder, subfolders and files


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
Run "icacls /help" to view definitions of other permission codes.'
  desc 'fix', 'Ensure the permissions on SYSVOL directory do not allow greater than read & execute for standard user accounts or groups. The defaults below meet this requirement.

Name - Authenticated Users
Permission - Read & execute
Apply To - This folder, subfolder and files

Name - Server Operators
Permission - Read & execute
Apply To - This folder, subfolder and files

Name - Administrators
Permission - Special
Apply To - This folder only
(Permission - Special - Permissions: all selected except Full control, Delete subfolders and files)

Name - CREATOR OWNER
Permission - Special (Full control in Detail view)
Apply To - Subfolders and files only

Name - Administrators
Permission - Special (Full control in Detail view)
Apply To - Subfolders and files only

Name - SYSTEM
Permission - Full control
Apply To - This folder, subfolders and files'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-48679r1_chk'
  tag severity: 'high'
  tag gid: 'V-27119'
  tag rid: 'SV-39858r2_rule'
  tag stig_id: 'DS00.0122_2008'
  tag gtitle: 'Directory Data Access Permissions - SYSVOL'
  tag fix_id: 'F-47802r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAN-1, ECCD-1, ECCD-2'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
