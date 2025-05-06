control 'SV-89181' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', %q(Review the permissions granted to users by the operating system/file system on the instance files, database files, database transaction log files, database audit log files, and database backup files.

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes, is permitted to read/view any of these files, this is a finding.

Note: When the instance and database directories are created by the DB2 database manager, the permissions are accurate and should not be changed.

Use the Following queries/commands to find the locations of instance directory, database directory, transaction logs directory, archive logs directory, audit logs directory and backup files location.
1. Instance Directory

On Linux and UNIX operating systems, the instance directory is located in the $INSTHOME/sqllib directory, where $INSTHOME is the home directory of the instance owner. 

For Windows run following command to show the parent directory of the instance directory:
  
     $db2set db2instprof 

e.g., for db2 instance "DB2"
C:\>db2set db2instprof
C:\ProgramData\IBM\DB2\DB2COPY1\DB2

The instance path in this case will be
C:\ProgramData\IBM\DB2\DB2COPY1\DB2

2. Database Directory 
For LINUX/UNIX Run Command:
  
     $db2 list db directory

Go to instance home directory then under this path, there is one or more db2 node directories.
The naming convention is NODExxxx, where xxxx is numeric
Identifying the DB2 node number.
Under the node directory, there are 3 types of subdirectories
  a) Same as database name.
  b) Database directories.  The naming convention is SQLxxxxx, where xxxxx is numeric.
  c) SQLDBDIR, the system database directory.
 
For Windows:
Under this local database directory, the next level is based on the instance name.

For example db2 instance "DB2", the path will be C:\DB2

Under this path, there is one or more db2 node directories.
The naming convention is NODExxxx, where xxxx is numeric
Identifying the DB2 node number.
Under the node directory, there are 3 types of subdirectories
  a) Same as database name.
  b) Database directories.  The naming convention is SQLxxxxx, where xxxxx is numeric.
  c) SQLDBDIR, the system database directory.

3. Audit Log Directory
Run following command:

     $db2audit describe

Find value of Audit Data Path and Audit Archive Path

4. Transaction Log Directory and Archive Logs Directory
Run the command:
     $db2 get db cfg 

Find value of following parameters and determine the directory locations.
Changed path to log files                  (NEWLOGPATH) 
Path to log files                                       
Overflow log path                     (OVERFLOWLOGPATH)
Mirror log path                         (MIRRORLOGPATH) 
Failover log archive path                (FAILARCHPATH)
First log archive method                 (LOGARCHMETH1)
Second log archive method                (LOGARCHMETH2)

5. Storage Files 
Run following SQL queries to find the value of tablespace containers and storage paths:

DB2> SELECT varchar(container_name,70) as container_name, varchar(tbsp_name,20) as tbsp_name
           FROM TABLE(MON_GET_CONTAINER('',-2))

           SELECT VARCHAR(STORAGE_GROUP_NAME, 30) AS STOGROUP, VARCHAR(DB_STORAGE_PATH, 40) AS STORAGE_PATH 
           FROM TABLE(ADMIN_GET_STORAGE_PATHS('',-1))

6.  Backup File Location
Run the following command and review the result for Location of Backups

     $db2 list history backup all for <database name>)
  desc 'fix', 'Configure the permissions granted by the operating system/file system on the database files, database transaction log files, database audit log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74433r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74507'
  tag rid: 'SV-89181r1_rule'
  tag stig_id: 'DB2X-00-005800'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-81107r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
