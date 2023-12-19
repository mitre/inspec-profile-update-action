control 'SV-25136' do
  title 'Permissions for system files and directories must conform to minimum requirements.'
  desc "Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications."
  desc 'check', %q(The default ACL settings are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).  If the default ACLs are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the sample directories below.  Non-privileged groups such as Users or Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.  (Individual accounts must not be used to assign permissions.)

Viewing in Windows Explorer:
Right click on the directory and select "Properties".
Select the "Security" tab, and the "Advanced" button.

C:\
Type - "Allow" for all
Inherited from - "<not inherited>" for all
Name - Permission - Apply to
Administrators - Full control - This folder, subfolders and files
SYSTEM - Full control - This folder, subfolders and files
Users - Read & execute - This folder, subfolders and files
Authenticated Users - Special - Subfolders and files only
(Special = all permissions except Full Control, Delete subfolders and files, Change permissions, and Take ownership when viewing permission details.)
Authenticated Users - Create folders / append data - This folder only

The Program Files, Program Files (x86), and Windows directories have the following default permissions:
Type - "Allow" for all
Inherited from - "<not inherited>" for all
Name - Permission - Apply to
TrustedInstaller - Special - This folder and subfolders
(Special = Full control when viewing permission details.)
SYSTEM - Special - This folder only
(Special = all permissions except Full Control, Delete subfolders and files, Change permissions, and Take ownership when viewing permission details.)
SYSTEM - Special - Subfolders and files only
(Special = Full control when viewing permission details.)
Administrators - Special - This folder only
(Special = all permissions except Full Control, Delete subfolders and files, Change permissions, and Take ownership when viewing permission details.)
Administrators - Special - Subfolders and files only
(Special = Full control when viewing permission details.)
Users - Read & execute - This folder, subfolders and files
CREATOR OWNER - Special - Subfolders and files only
(Special = Full control when viewing permission details.)


Alternately use Icacls.

In a Command prompt (admin)
Enter icacls followed by the directory.

icacls c:\
icacls "c:\program files" of "c:\program files (x86)"
icacls c:\windows

The following results will be displayed as each is entered:

c:\
BUILTIN\Administrators:(F)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Users:(OI)(CI)(RX)
NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
NT AUTHORITY\Authenticated Users:(AD)
Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
Successfully processed 1 files; Failed processing 0 files

c:\program files, c:\program files (x86), and c:\windows
NT SERVICE\TrustedInstaller:(F)
NT SERVICE\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(M)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(M)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
BUILTIN\Users:(RX)
BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files

If a permission setting prevents a site's applications from performing properly, settings must only be changed to the minimum necessary for the application to function.  Each exception must be documented with the ISSO.)
  desc 'fix', 'Maintain the default file ACLs and configure the Security Option: "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (V-3377).'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62057r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1130'
  tag rid: 'SV-25136r2_rule'
  tag gtitle: 'System File ACLs'
  tag fix_id: 'F-66955r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
