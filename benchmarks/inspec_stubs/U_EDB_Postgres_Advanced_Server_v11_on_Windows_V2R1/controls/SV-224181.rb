control 'SV-224181' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Verify User ownership, Group ownership, and permissions on the <postgressql data directory> directory. Note that the default location for the EDB postgresql data directory is found in the directory where EDB Postgres Advanced Server is installed. The location of the data directory for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW data_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

1) Check Ownership of Postgresql Data Directory:
First, determine ownership of the postgresql data directory folder. This can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the postgresql data directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Details" tab. 
 Note the Value of the Owner field.

Using the Windows command prompt, enter the following command:

 dir "<postgresql data directory>" /Q /S

 Note: The above command will list all of the files and folders under the data directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation. If the owner listed for the folder and any of the files and subfolders in the data directory is not the database service account and the configuration has not been documented and approved, this is a finding.

2) Check Permissions on Postgresql Data Directory
Check the permissions assigned to the postgresql data directory folder and its content. This can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the postgresql data directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Security" tab.
 Review the users and groups and permissions assigned to them for the folder.

Using a Windows command prompt, the following command may be used to list file permissions:

 icacls "<postgresql data directory>"
 icacls "<postgresql data directory>\\*" 
 Review the users and groups and permissions assigned to them for the file(s).

 Note: The above commands will list the permissions for all files and folders under the data directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation.
Verify that at most the following permissions are applied:
 NT AUTHORITY/NetworkService (or configured database service account) (Full Control)
 Administrators (Full Control)
 Users (none)

If other permissions have been granted to other users or groups and the permission setting has not been documented with sufficient documentation and approved, this is a finding.'
  desc 'fix', 'If the postgresql data directory and its contents are not owned by the database service account or other user as documented and approved in the system documentation, change ownership to an authorized user.

Modify permissions on the data directory and its contents to meet the requirement to protect against unauthorized access.

This may be done using Windows Explorer:
 Browse to the directory where the EDB audit directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Security" tab.
 Modify the security permissions to:
 NT AUTHORITY/NetworkService (or configured database service account) (Full Control)
 Administrators (Full Control)
 Users (none)

Alternatively, the Windows ICACLS command may be used to modify permissions on folders and files using the Windows command prompt.

If other permissions have been granted to other users or groups, ensure that the system documentation is updated to note the organizationally approved permission setting and corresponding justification of the permission settings for this requirement.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25854r495561_chk'
  tag severity: 'medium'
  tag gid: 'V-224181'
  tag rid: 'SV-224181r508023_rule'
  tag stig_id: 'EP11-00-006100'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-25842r495562_fix'
  tag 'documentable'
  tag legacy: ['V-100385', 'SV-109489']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
