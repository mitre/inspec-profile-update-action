control 'SV-224832' do
  title 'Permissions for the system drive root directory (usually C:\\) must conform to minimum requirements.'
  desc %q(Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.

The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (WN16-SO-000290).

)
  desc 'check', %q(The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (WN16-SO-000290).

Review the permissions for the system drive's root directory (usually C:\\). Non-privileged groups such as Users or Authenticated Users must not have greater than "Read & execute" permissions except where noted as defaults. (Individual accounts must not be used to assign permissions.)

If permissions are not as restrictive as the default permissions listed below, this is a finding.

Viewing in File Explorer:

View the Properties of the system drive's root directory.

Select the "Security" tab, and the "Advanced" button.

Default permissions:
C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders, and files
Administrators - Full control - This folder, subfolders, and files
Users - Read & execute - This folder, subfolders, and files
Users - Create folders/append data - This folder and subfolders
Users - Create files/write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only

Alternately, use icacls:

Open "Command Prompt (Admin)".

Enter "icacls" followed by the directory:

"icacls c:\"

The following results should be displayed:

c:\
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Administrators:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
BUILTIN\Users:(CI)(AD)
BUILTIN\Users:(CI)(IO)(WD)
CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files)
  desc 'fix', %q(Maintain the default permissions for the system drive's root directory and configure the Security Option "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (WN16-SO-000290).

Default Permissions
C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders, and files
Administrators - Full control - This folder, subfolders, and files
Users - Read & execute - This folder, subfolders, and files
Users - Create folders/append data - This folder and subfolders
Users - Create files/write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only)
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26523r465398_chk'
  tag severity: 'medium'
  tag gid: 'V-224832'
  tag rid: 'SV-224832r852289_rule'
  tag stig_id: 'WN16-00-000160'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-26511r465399_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124']
  tag 'documentable'
  tag legacy: ['SV-87901', 'V-73249']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
