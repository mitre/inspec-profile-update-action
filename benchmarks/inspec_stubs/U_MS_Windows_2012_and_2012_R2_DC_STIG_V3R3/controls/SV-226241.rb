control 'SV-226241' do
  title 'Permissions for program file directories must conform to minimum requirements.'
  desc %q(Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.

The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).)
  desc 'check', 'The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).  If the default ACLs are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the program file directories (Program Files and Program Files (x86)).  Nonprivileged groups such as Users or Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.  (Individual accounts must not be used to assign permissions.)

Viewing in File Explorer:
For each folder, view the Properties.
Select the "Security" tab, and the "Advanced" button.

Default Permissions:
\\Program Files and \\Program Files (x86)
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
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files

Alternately, use Icacls:

Open a Command prompt (admin).
Enter icacls followed by the directory:

icacls "c:\\program files"
icacls "c:\\program files (x86)"

The following results should be displayed as each is entered:

c:\\program files 
NT SERVICE\\TrustedInstaller:(F)
NT SERVICE\\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\\SYSTEM:(M)
NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\\Administrators:(M)
BUILTIN\\Administrators:(OI)(CI)(IO)(F)
BUILTIN\\Users:(RX)
BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files'
  desc 'fix', 'Maintain the default permissions for the program file directories and configure the Security Option: "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (V-3377).

Default Permissions:
\\Program Files and \\Program Files (x86)
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
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27943r476567_chk'
  tag severity: 'medium'
  tag gid: 'V-226241'
  tag rid: 'SV-226241r794555_rule'
  tag stig_id: 'WN12-GE-000007'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-27931r476568_fix'
  tag 'documentable'
  tag legacy: ['SV-52135', 'V-40177']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
