control 'SV-225420' do
  title 'Permissions for system drive root directory (usually C:\\) must conform to minimum requirements.'
  desc %q(Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.

The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).)
  desc 'check', %q(The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).  If the default ACLs are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the system drive's root directory (usually C:\\).  Nonprivileged groups such as Users or Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.  (Individual accounts must not be used to assign permissions.)

Viewing in File Explorer:
View the Properties of system drive root directory.
Select the "Security" tab, and the "Advanced" button.

C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders and files
Administrators - Full control - This folder, subfolders and files
Users - Read & execute - This folder, subfolders and files
Users - Create folders / append data - This folder and subfolders
Users - Create files / write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only

Alternately, use Icacls:

Open a Command prompt (admin).
Enter icacls followed by the directory:

icacls c:\

The following results should be displayed:

c:\
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Administrators:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
BUILTIN\Users:(CI)(AD)
BUILTIN\Users:(CI)(IO)(WD)
CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files)
  desc 'fix', %q(Maintain the default permissions for the system drive's root directory and configure the Security Option: "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (V-3377).

Default Permissions
C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders and files
Administrators - Full control - This folder, subfolders and files
Users - Read & execute - This folder, subfolders and files
Users - Create folders / append data - This folder and subfolders
Users - Create files / write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only)
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27119r471602_chk'
  tag severity: 'medium'
  tag gid: 'V-225420'
  tag rid: 'SV-225420r852234_rule'
  tag stig_id: 'WN12-GE-000006'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-27107r471603_fix'
  tag 'documentable'
  tag legacy: ['SV-52136', 'V-40178']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
