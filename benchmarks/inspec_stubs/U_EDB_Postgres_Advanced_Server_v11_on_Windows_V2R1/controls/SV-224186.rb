control 'SV-224186' do
  title 'The EDB Postgres Advanced Server must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.'
  desc %q(If EDB Postgres Advanced Server provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Some default EDB Postgres Advanced Server error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information.

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant.

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified according to organization-specific needs, with appropriate approval.

In addition to ensuring that access to EDB Postgres Advanced Server database and audit logs is restricted to authorized users and that EDB Postgres Advanced Server is configured to emit minimal information to clients related to Postgres generated errors, custom database code and external application code should also be designed to not emit detailed error messages to a client. This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.)
  desc 'check', '# Verify client_min_messages setting
Check the level of detail for errors exposed to clients, connect to the database as a database superuser using psql and execute the following psql command:

 SHOW client_min_messages

If client_min_messages is set to LOG or DEBUG, this is a finding.

# Verify access to database logs and audit log restricted to authorized users
Verify that only authorized users are able to access EDB Postgres Advanced Server database and audit logs that may contain detailed error messages. By default, these logs are written to directories under the EDB Postgres Advanced Server data directory. The full path of the data directory can be determined by connecting to the database as a database superuser using psql and execute the following psql command:

 SHOW data_directory

To check the access permissions assigned to the database logs, first determine where the logs are being written by connecting to the database as a database superuser using psql and execute the following psql command:

 SHOW log_destination

# Verify access to database logs (stderr or csvlog)
If the log_destination parameter is set to "stderr" or "csvlog", next determine the directory on the files system where the logs are being written by connecting to the database as a database superuser using psql and execute the following psql command:

 SHOW log_directory

If the log_directory parameter is set to a relative path, database logs have been configured to be written to the named directory under the EDB Postgres Advanced Server data directory. 

If the log_directory parameter is set to an absolute path, database logs have been configured to be written to that location.

Next, determine ownership of the log directory folder. This can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the log directory folder is located.
 Select and right-click on the folder, select "Properties", select the "Security" tab, and select the "Advanced" button. 
 Note the Value of the Owner field.

Using the Windows command prompt, enter the following command, replacing <EDB log directory> with the correct path for the log directory:

 dir "<EDB log directory>" /Q /S

 Note: The above command will list all of the files and folders under the audit directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation. If the owner listed for the folder and any of the files and subfolders in the EDB log directory and its content is not the service account responsible for running the Advanced Server database service this is a finding. 

Next, check the permissions assigned to the EDB log directory folder and its content. Again, this can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the EDB log directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Security" tab.
 Review the users and groups and permissions assigned to them for the folder.

Using a Windows command prompt, the following command may be used to list file permissions:

 icacls "<EDB log directory>"
 icacls "<EDB log directory>\\*" 
 Review the users and groups and permissions assigned to them for the file(s).

 Note: The above commands will list the permissions for all files and folders under the log directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation. 
If read or greater permissions are granted to Everyone or to the Users group, this is a finding.
If any account other than the database service account, Administrators, or other documented users are listed as having Read permission, this is a finding.
If any account other than the database service account or other documented users are listed as having the Full Control permission, this is a finding.
If any permissions are listed for any account other than the database service account that are not identified in the system documentation as being approved for the permission, this is a finding.

# Verify access to database logs (eventlog)
If the log_destination parameter is set to "eventlog", logs are written to the Windows Application event log. Review system security documentation and the Windows event log local and group policy settings. If the configured Windows Event Log policies give access to the Windows Application event log to any system users who are not documented as approved to view EDB Postgres Advanced Server logs, this is a finding.

# Verify access to audit logs
First determine the directory on the files system where the EDB Audit logs are being written by connecting to the database as a database superuser using psql and execute the following psql command:

 SHOW edb_audit_directory

If the edb_audit_directory parameter is set to a relative path, database logs have been configured to be written to the named directory under the EDB Postgres Advanced Server data directory. 

If the log_directory parameter is set to an absolute path, database logs have been configured to be written to that location.

Next, determine ownership of the EDB audit directory folder. This can be done using Windows Explorer or via a Windows command prompt.

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
If any permissions are listed for any account other than the database service account that are not identified in the system documentation as being approved for the permission, this is a finding.

# Verify custom database code and application does not display detailed error messages
Check custom database code and application code to determine if detailed error messages are ever displayed to unauthorized individuals.

If detailed error messages are displayed to individuals not authorized to view them, this is a finding.'
  desc 'fix', %q(# Set client_min_messages
To set the level of detail for errors messages exposed to clients, connect to the database as a database superuser using psql and execute the following commands:

 ALTER SYSTEM SET client_min_messages = notice;
 SELECT pg_reload_conf();

# Update EDB Postgres Advanced Server database log permissions.
If the EDB Postgres Advanced Server log_destination parameter is set to "stderr" or "csvlog":

1) Change ownership of EDB Postgres Advanced Server database log directory and its contents to the database service account if they are not owned by the database service account.

If the EDB Postgres Advanced Server database log directory and its contents are not owned by the database service account, change ownership to the service account responsible for running the Advanced Server database service.

This may be done using Windows Explorer:
 Browse to the directory where the log directory folder is located.
 Select and right-click on the folder, select "Properties", select the "Securities" tab, and select the "Advanced" button.
 Select the "Change" link shown next to the owner of the folder to change the folder's owner.

Alternatively, the Windows TAKEOWN command or the ICACLS command (with the /SETOWNER option) may be used to change ownership of folders and files using the Windows command prompt.

2) Modify permissions on the EDB Postgres Advanced Server database log directory and its contents to meet the requirement to protect against unauthorized access.

This may be done using Windows Explorer:
 Browse to the directory where the log directory folder is located.
 Select and right-click on the folder, select "Properties", and select the "Security" tab.
 Modify the security permissions to:
 NT AUTHORITY/NetworkService (or configured database service account) (Full Control)
 Administrators (Read)
 Users (none)

Alternatively, the Windows ICACLS command may be used to modify permissions on folders and files using the Windows command prompt.

If the EDB Postgres Advanced Server log_destination parameter is set to "eventlog", update the Windows policy settings to only allow access to the Windows Application event log to authorized users.

If other permissions have been granted to other users or groups, ensure that the system documentation is updated to note the organizationally approved permission setting and corresponding justification of the permission settings for this requirement.

# Update EDB Audit log permissions.
1) Change ownership of EDB Audit directory and its contents to the database service account if they are not owned by the database service account.

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

If other permissions have been granted to other users or groups, ensure that the system documentation is updated to note the organizationally approved permission setting and corresponding justification of the permission settings for this requirement.

# Update custom database code and application code
Configure custom database code and associated application code not to display detailed error messages to those not authorized to view them.)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25859r495576_chk'
  tag severity: 'medium'
  tag gid: 'V-224186'
  tag rid: 'SV-224186r508023_rule'
  tag stig_id: 'EP11-00-006600'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-25847r495577_fix'
  tag 'documentable'
  tag legacy: ['V-100395', 'SV-109499']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
