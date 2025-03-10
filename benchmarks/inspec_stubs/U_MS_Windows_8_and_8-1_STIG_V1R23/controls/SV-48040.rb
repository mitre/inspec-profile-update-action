control 'SV-48040' do
  title 'Permissions for system files and directories must conform to minimum requirements.'
  desc "Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications."
  desc 'check', %q(The default ACL settings are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).  If the default ACLs are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the sample directories below.  Non-privileged groups such as Users or Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.  (Individual accounts must not be used to assign permissions.)

Viewing in File Explorer:
Select the "Security" tab, and the "Advanced" button.

C:\
Type - "Allow" for all
Inherited from  - "None" for all
Principal - Access - Applies to
Administrators - Full control - This folder, subfolders and files
SYSTEM  - Full control - This folder, subfolders and files
Users - Read & execute - This folder, subfolders and files
Authenticated Users - Modify - Subfolders and files only
Authenticated Users - Create folders / append data - This folder only

\Program Files
Type - "Allow" for all
Inherited from  - "None" for all
Principal - Access - Applies to
TrustedInstaller  - Full control - This folder and subfolders
SYSTEM  - Modify - This folder only
SYSTEM  - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute -  This folder, subfolders and files

\Windows
Type - "Allow" for all
Inherited from  - "None" for all
Principal  Access   Applies to
TrustedInstaller  - Full control - This folder and subfolders
SYSTEM  - Modify - This folder only
SYSTEM  - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute -  This folder, subfolders and files


Alternately use Icacls.

In a Command prompt (admin)
Enter icacls followed by the directory.

icacls c:\
icacls "c:\program files"
icacls c:\windows

The following results will be displayed as each is entered:

c:\
BUILTIN\Administrators:(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
NT AUTHORITY\Authenticated Users:(AD)
Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
Successfully processed 1 files; Failed processing 0 files

c:\program files 
NT SERVICE\TrustedInstaller:(F)
NT SERVICE\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(M)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(M)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
BUILTIN\Users:(RX)
BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files

c:\windows
NT SERVICE\TrustedInstaller:(F)
NT SERVICE\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(M)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(M)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
BUILTIN\Users:(RX)
BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files

If an ACL setting prevents a site's applications from performing properly, settings must only be changed to the minimum necessary for the application to function.  Each exception must be documented with the ISSO.)
  desc 'fix', 'Maintain the default file ACLs and configure the Security Option: "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (V-3377).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44779r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1130'
  tag rid: 'SV-48040r2_rule'
  tag stig_id: 'WN08-GE-000010'
  tag gtitle: 'System File ACLs'
  tag fix_id: 'F-41178r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
