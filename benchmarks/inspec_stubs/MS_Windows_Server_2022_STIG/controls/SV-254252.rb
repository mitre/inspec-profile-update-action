control 'SV-254252' do
  title 'Windows Server 2022 permissions for program file directories must conform to minimum requirements.'
  desc %q(Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.

The default permissions are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (WN22-SO-000240).

)
  desc 'check', %q(The default permissions are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (WN22-SO-000240).

Review the permissions for the program file directories (Program Files and Program Files [x86]). Nonprivileged groups such as Users or Authenticated Users must not have greater than "Read & execute" permissions. Individual accounts must not be used to assign permissions.

If permissions are not as restrictive as the default permissions listed below, this is a finding.

Viewing in File Explorer:

For each folder, view the Properties.

Select the "Security" tab, and the "Advanced" button.

Default permissions:
\Program Files and \Program Files (x86)
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

TrustedInstaller - Full control - This folder and subfolders
SYSTEM - Modify - This folder only
SYSTEM - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files
ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files

Alternately, use icacls:

Open a Command prompt (admin).

Enter "icacls" followed by the directory:

'icacls "c:\program files"'
'icacls "c:\program files (x86)"'

The following results must be displayed for each when entered:

c:\program files (c:\program files (x86))
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
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files)
  desc 'fix', 'Maintain the default permissions for the program file directories and configure the Security Option "Network access: Let Everyone permissions apply to anonymous users" to "Disabled" (WN22-SO-000240).

Default permissions:
\\Program Files and \\Program Files (x86)
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

TrustedInstaller - Full control - This folder and subfolders
SYSTEM - Modify - This folder only
SYSTEM - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders, and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files
ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57737r848570_chk'
  tag severity: 'medium'
  tag gid: 'V-254252'
  tag rid: 'SV-254252r848572_rule'
  tag stig_id: 'WN22-00-000150'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-57688r848571_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124']
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
