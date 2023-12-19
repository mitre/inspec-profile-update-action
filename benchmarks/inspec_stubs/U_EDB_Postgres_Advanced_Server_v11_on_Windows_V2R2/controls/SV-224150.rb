control 'SV-224150' do
  title 'The audit information produced by the EDB Postgres Advanced Server must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys to make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'The location of the EDB audit directory is specified via the edb_audit_directory parameter. By default, this parameter is set to "edb_audit", which results in a directory name "edb_audit" being created under the postgresql data directory. 

The location of the EDB Audit directory for a running EDB Postgres Advanced Server instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW edb_audit_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS). 

Note that the default location for the EDB postgresql data directory is found in the directory where EDB Postgres Advanced Server is installed. The location of the data directory for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW data_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If the default path is used for the postgresql data directory and the default setting of "edb_audit" is used for the edb_audit_directory parameter, the path to the EDB audit directory would be <EDB Postgres data directory>\\edb_audit. Depending on the version of EPAS that is installed, the options that were selected during installation, and the edb_audit_directory parameter setting, the path to the data directory and the EDB audit directory may be different.

First, determine ownership of the EDB audit directory folder. This can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the EDB audit directory folder is located.
 Select and right-click on the folder, select "Properties", select the "Security" tab, and select the "Advanced" button. 
 Note the Value of the Owner field.

Using the Windows command prompt, enter the following command, replacing <EDB Audit directory> with the correct path for the EDB audit directory:

 dir "<EDB Audit directory>" /Q /S

 Note: The above command will list all of the files and folders under the audit directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation. If the owner listed for the folder and any of the files and subfolders in the EDB audit directory and its content is not the service account responsible for running the Advanced Server database service this is a finding. 

Next, check the permissions assigned to the EDB audit directory folder and its content. Again, this can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the EDB audit directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Security" tab.
 Review the users and groups and permissions assigned to them for the folder.

Using a Windows command prompt, the following command may be used to list file permissions:

 icacls "<EDB Audit directory>"
 icacls "<EDB Audit directory>\\*" 
 Review the users and groups and permissions assigned to them for the file(s).

 Note: The above commands will list the permissions for all files and folders under the data directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation. 
If read or greater permissions are granted to Everyone or to the Users group, this is a finding.
If any account other than the database service account, Administrators, or other documented users are listed as having Read permission, this is a finding.
If any account other than the database service account or other documented users are listed as having the Full Control permission, this is a finding.
If any permissions are listed for any account other than the database service account that are not identified in the system documentation as being approved for the permission, this is a finding.'
  desc 'fix', %q(1) Change ownership of EDB Audit directory and its contents to the database service account if they are not owned by the database service account.

If the EDB Audit directory and its contents are not owned by the database service account, change ownership to the service account responsible for running the Advanced Server database service.

This may be done using Windows Explorer:
 Browse to the directory where the EDB audit directory folder is located.
 Select and right-click on the folder, select "Properties", select the "Securities" tab, and select the "Advanced" button.
 Select the "Change" link shown next to the owner of the folder to change the folder's owner.

Alternatively, the Windows TAKEOWN command or the ICACLS command (with the /SETOWNER option) may be used to change ownership of folders and files using the Windows command prompt.

2) Modify permissions on the EDB Audit directory and its contents to meet the requirement to protect against unauthorized access.

This may be done using Windows Explorer:
 Browse to the directory where the EDB audit directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Security" tab.
 Modify the security permissions to:
 NT AUTHORITY/NetworkService (or configured database service account) (Full Control)
 Administrators (Read)
 Users (none)

Alternatively, the Windows ICACLS command may be used to modify permissions on folders and files using the Windows command prompt.

If other permissions have been granted to other users or groups, ensure that the system documentation is updated to note the organizationally approved permission setting and corresponding justification of the permission settings for this requirement.)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25823r495470_chk'
  tag severity: 'medium'
  tag gid: 'V-224150'
  tag rid: 'SV-224150r508023_rule'
  tag stig_id: 'EP11-00-002800'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-25811r495471_fix'
  tag 'documentable'
  tag legacy: ['SV-109431', 'V-100327']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
