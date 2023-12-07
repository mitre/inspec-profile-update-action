control 'SV-224135' do
  title 'The EDB Postgres Advanced Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict the types of roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', %q(Check DBMS settings and documentation to determine whether designated personnel can select which auditable events are being audited. If designated personnel are not able to configure auditable events, this is a finding.

If EDB Audit is being used, the EDB Audit settings may only be configured by Operating System users authorized to edit the cluster's postgresql.conf file or by database superusers. As such, the permissions associated with the postgresql.conf file must be checked as well as the database roles assigned to database users. In addition, database parameters, including the EDB Audit settings, may be specified via server startup command options. Users assigned "Modify" permission or greater on the postgresql data directory and its contents will be able to start the postgres database cluster. Therefore, only authorized users should be assigned these permissions.

1) Check Postgresql Data Directory Ownership and Permissions:
First, determine ownership of the postgresql data directory folder. This can be done using Windows Explorer or via a Windows command prompt.

Note: The default location for the EDB postgresql data directory is found in the directory where EDB Postgres Advanced Server is installed. The location of the data directory for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW data_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

Using Windows Explorer:
Browse to the directory where the postgresql data directory folder is located.
Select and right-click on the folder, select "Properties", select the "Security" tab, and select the "Advanced" button. 
Note the Value of the Owner field.

Using the Windows command prompt, enter the following command:

 dir "<postgresql data directory>" /Q /S

Note: The above command will list all of the files and folders under the data directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation. If the owner listed for the folder and any of the files and subfolders in the data directory is not authorized to own the folder and its content, this is a finding.

Next, check the permissions assigned to the postgresql data directory folder and its content. Again, this can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
Browse to the directory where the postgresql data directory folder is located.
Select and right-click on the folder, select "Properties", and select the "Security" tab.
Review the users and groups and permissions assigned to them for the folder.

Using a Windows command prompt, the following command may be used to list file permissions:

 icacls "<postgresql data directory>"
 icacls "<postgresql data directory>\*" 
 Review the users and groups and permissions assigned to them for the file(s).
Note: The above commands will list the permissions for all files and folders under the data directory. To make the output of this command easier to review, it may be redirected to a text file.

Review the system security documentation.
If permissions are granted to Everyone or to the Users group, this is a finding.
If any account other than the database service account, software owner accounts, Administrators, DBAs, System group, or other documented users authorized to start a postgresql database cluster are listed, this is a finding.

2) Check Postgresql Configuration File Ownership and Permissions:
First, determine ownership of the postresql.conf file(s). This can be done using Windows Explorer or via a Windows command prompt.

Note that the default location for the postgresql.conf file is in the postgresql data directory. The location of the postgresql.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW config_file"

Using Windows Explorer:
 Browse to the directory where the postgresql.conf file is located.
 Select and right-click on the postgresql.conf file, select "Properties", and select the "Details" tab. 
 Note the Value of the Owner field.

Using the Windows command prompt, enter the following command:

 dir "<directory where postgresql.conf is located>\postgresql*.conf" /Q

Review the system security documentation. If the owner listed for the file(s) is not authorized to own the file(s) this is a finding.

Next, check the permissions assigned to the postgresql configuration files. This can be done using Windows Explorer or via a Windows command prompt.

Using Windows Explorer:
 Browse to the directory where the postgresql.conf file is located.
 Select and right-click on the postgresql.conf file, select "Properties", and select the "Security" tab.
 Review the users and groups and permissions assigned to them for the file.

Using a Windows command prompt, the following command may be used to list file permissions:

 icacls "<directory where postgresql.conf is located>\postgresql*.conf"

 Review the users and groups and permissions assigned to them for the file(s).

Review the system security documentation.
If permissions are granted to Everyone or to the Users group, this is a finding.
If any account other than the database service account, software owner accounts, Administrators, DBAs, System group, or other documented users authorized to make changes to the configuration parameters of this database are listed, this is a finding.

Note: Since the postgresql.conf file may utilize include and include_dir statements to include additional parameter organizational specified configuration files, review the contents of the postgresql.conf file to determine if any uncommented include or include_dir statements are specified in the file. If these statements are found, the file ownership and permissions assigned to the files specified by these statements should also be checked. If any unauthorized users are owners of the files or have permission to edit the files this is a finding.

3) Check Database Users Assigned Superuser Privileges:
Use psql to connect to the db as enterprisedb and run this command:

 \du

If any unauthorized users/roles are listed as a superuser, this is a finding.)
  desc 'fix', "If a non-EDB provided database auditing solution or a custom auditing solution is being used, configure the DBMS's settings according to the documentation provided for those solutions to allow designated personnel to select which auditable events are audited.

If EDB Auditing is being used, perform the following actions as necessary to address any findings:
1) Postgresql Data Directory Ownership and Permissions:
If the postgresql data directory and its contents are owned by unauthorized users, change ownership to an authorized user.

Restrict access on the postgresql data directory to the database service account, software owner accounts, Administrators, DBAs, System group, or other documented users authorized to start a postgresql database cluster.

2) Postgresql Configuration File Ownership and Permissions:
If the postgresql configuration file(s) is owned by an unauthorized user, change ownership to an authorized user.

Restrict write access on Postgres configuration file(s) the database service account, software owner accounts, Administrators, DBAs, System group, or other documented users authorized to edit the file(s).

3) Database Users Assigned Superuser Privileges:
Remove superuser rights from unauthorized database users via the ALTER ROLE or ALTER USER SQL command.

The syntax is:
ALTER ROLE <role> NOSUPERUSER

or

ALTER USER <user> NOSUPERUSER

Example: 
ALTER ROLE testuser NOSUPERUSER;

OR 

ALTER USER testuser NOSUPERUSER;

See PostgreSQL and/or EDB Postgres Advanced Server documentation for details."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25808r495425_chk'
  tag severity: 'medium'
  tag gid: 'V-224135'
  tag rid: 'SV-224135r508023_rule'
  tag stig_id: 'EP11-00-001100'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-25796r495426_fix'
  tag 'documentable'
  tag legacy: ['SV-109401', 'V-100297']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
