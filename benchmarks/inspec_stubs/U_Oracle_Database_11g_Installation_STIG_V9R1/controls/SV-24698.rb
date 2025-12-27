control 'SV-24698' do
  title 'Access to external DBMS executables should be disabled or restricted.'
  desc 'The Oracle external procedure capability provides use of the Oracle process account outside the operation of the DBMS process. You can use it to submit and execute applications stored externally from the database under operating system controls. The external procedure process is the subject of frequent and successful attacks as it allows unauthenticated use of the Oracle process account on the operating system. As of Oracle version 11.1, the external procedure agent may be run directly from the database and not require use of the Oracle listener. This reduces the risk of unauthorized access to the procedure from outside of the database process.'
  desc 'check', 'Review the System Security Plan to determine if the use of the external procedure agent is authorized.

Review the ORACLE_HOME/bin directory or search the ORACLE_BASE path for the executable extproc (UNIX) or extproc.exe (Windows).

If external procedure agent is not authorized for use in the System Security Plan and the executable file exists and is not restricted, this is a Finding.

If use of the external procedure agent is authorized, ensure extproc is restricted to execution of authorized applications.

External jobs are run using the account nobody by default.

Review the contents of the file ORACLE_HOME/rdbms/admin/externaljob.ora for the lines run_user= and run_group=.

If the user assigned to these parameters is not "nobody", this is a Finding.

For versions 11.1 and later, the external procedure agent (extproc executable) is available directly from the database and does not require definition in the listener.ora file for use.

Review the contents of the file ORACLE_HOME/hs/admin/extproc.ora.

If the file does not exist, this is a Finding.

If the following entry does not appear in the file, this is a Finding:

EXTPROC_DLLS=ONLY:[dll full file name1]:[dll full file name2]:..

[dll full file name] represents a full path and file name.

This list of file names is separated by ":".

NOTE: If "ONLY" is specified, then the list is restricted to allow execution of only the DLLs specified in the list and is not a Finding. If "ANY" is specified, then there are no restrictions for execution except what is controlled by operating system permissions and is a Finding. If no specification is made, any files located in the %ORACLE_HOME%\\bin directory on Windows systems or $ORACLE_HOME/lib directory on UNIX systems can be executed (the default) and is a Finding.

Ensure that EXTPROC is not accessible from the listener.

Review the listener.ora file. If any entries reference "extproc", this is a Finding.

NOTE: Bug 7560049 may cause external procedures in 11g not to work on certain platforms. Fix will be in Oracle 11g Release 2. If external procedures are required and you are experiencing this bug, then follow instructions for configuring external procedures for versions earlier than 11.1 and document as authorized in the System Security Plan.

Determine if the external procedure agent is in use per Oracle 10.x conventions.

Review the listener.ora file.

If any entries reference "extproc", then the agent is in use.

If external procedure agent is not authorized for use in the System Security Plan and references to "extproc" exist, this is a Finding.

Sample listener.ora entries with extproc included:

LISTENER =
(DESCRIPTION =
(ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1521))
)
EXTLSNR =
(DESCRIPTION =
(ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC))
)
SID_LIST_LISTENER =
(SID_LIST =
(SID_DESC =
(GLOBAL_DBNAME = ORCL)
(ORACLE_HOME = /home/oracle/app/oracle/product/11.1.0/db_1)
(SID_NAME = ORCL)
)
)
SID_LIST_EXTLSNR =
(SID_LIST =
(SID_DESC =
(PROGRAM = extproc)
(SID_NAME = PLSExtProc)
(ORACLE_HOME = /home/oracle/app/oracle/product/11.1.0/db_1)
(ENVS="EXTPROC_DLLS=ONLY:/home/app1/app1lib.so:/home/app2/app2lib.so,
LD_LIBRARY_PATH=/private/app2/lib:/private/app1,
MYPATH=/usr/fso:/usr/local/packages")
)
)

Sample tnsnames.ora entries with extproc included:

ORCL =
(DESCRIPTION =
(ADDRESS_LIST =
(ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1521))
)
(CONNECT_DATA =
(SERVICE_NAME = ORCL)
)
)
EXTPROC_CONNECTION_DATA =
(DESCRIPTION =
(ADDRESS_LIST =
(ADDRESS = (PROTOCOL = IPC)(KEY = extproc))
)
(CONNECT_DATA =
(SERVER = DEDICATED)
(SERVICE_NAME = PLSExtProc)
)
)

If EXTPROC is in use, confirm that a listener is dedicated to serving the external procedure agent (as shown above).

View the protocols configured for the listener.

For the listener to be dedicated, the only entries will be to specify extproc.

If there is not a dedicated listener in use for the external procedure agent, this is a Finding.

If the PROTOCOL= specified is other than IPC, this is a Finding.

Verify and ensure extproc is restricted executing authorized external applications only and extproc is restricted to execution of authorized applications.

Review the listener.ora file.

If the following entry does not exist, this is a Finding:

EXTPROC_DLLS=ONLY:[dll full file name1]:[dll full file name2]:...

NOTE: [dll full file name] represents a full path and file name. This list of file names is separated by ":".

NOTE: If "ONLY" is specified, then the list is restricted to allow execution of only the DLLs specified in the list and is not a Finding. If "ANY" is specified, then there are no restrictions for execution except what is controlled by operating system permissions and is a Finding. If no specification is made, any files located in the %ORACLE_HOME%\\bin directory on Windows systems or $ORACLE_HOME/lib directory on UNIX systems can be executed (the default) and is a Finding.

View the listener.ora file (usually in ORACLE_HOME/network/admin or directory specified by the TNS_ADMIN environment variable).

If multiple listener processes are running, then the listener.ora file for each must be viewed.

For each process, determine the directory specified in the ORACLE_HOME or TNS_ADMIN environment variable defined for the process account to locate the listener.ora file.'
  desc 'fix', 'If the use of external procedure agent is required, then authorize and document the requirement in the System Security Plan.

If the external procedure agent must be accessible to the Oracle listener, then specify this and authorize it in the System Security Plan.

If use of the Oracle External Procedure agent is not required:

 - Stop the Oracle Listener process
 - Remove all references to extproc in the listener.ora and tnsnames.ora files
 - Alter the permissions on the executable files:
  UNIX - Remove read/write/execute permissions from owner, group and world
  Windows - Remove Groups/Users from the executable (except groups SYSTEM and ADMINISTRATORS) and allow READ [only] for SYSTEM and ADMINISTRATORS groups

If required:

 - Restrict extproc execution to only authorized applications.
 - Specify EXTPROC_DLLS=ONLY: [list of authorized DLLS] in the extproc.ora and the listener.ora files
 - Create a separate, dedicated listener for use by the external procedure agent

Please see the Oracle Net Services Administrators Guides, External Procedures section for detailed configuration information.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26370r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15618'
  tag rid: 'SV-24698r1_rule'
  tag stig_id: 'DG0099-ORACLE11'
  tag gtitle: 'DBMS access to external local executables'
  tag fix_id: 'F-22704r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
