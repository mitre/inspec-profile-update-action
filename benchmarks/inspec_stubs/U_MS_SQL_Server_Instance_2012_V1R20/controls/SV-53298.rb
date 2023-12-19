control 'SV-53298' do
  title 'The OS must limit privileges to change SQL Server software resident within software libraries (including privileged programs).'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

If any user were allowed to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.  The DBMS software libraries contain the executables used by the DBMS to operate. Unauthorized access to the libraries can result in compromised installations. This may in turn jeopardize data stored in the DBMS and/or operation of the host system.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Of particular note in this context is that any software installed for auditing and/or audit file management must be protected and monitored.'
  desc 'check', %q(Obtain the SQL Server software directory location: from a command prompt, open the registry editor by typing regedit.exe and pressing [ENTER]. Navigate to the following registry location:
HKEY_LOCAL_MACHINE
>> SOFTWARE
>> Microsoft
>> Microsoft SQL Server
>> [INSTANCE NAME]
>> Setup
>> SQLBinRoot

In the registry tree, the [INSTANCE NAME] for a SQL Server 2012 database engine instance is normally shown as "MSSQL11" followed by a period and the name that was specified for the SQL Server service at installation time. If multiple SQL Server instances are installed, each will have its own [INSTANCE NAME] node and subtree in the registry.

The value in the Data column for the SQLBinRoot registry entry is the file system path for the SQL Server 2012 binaries. Navigate to that folder location using a command prompt or Windows Explorer. The following instructions assume that Windows Explorer is used.

Verify that files and folders that are part of the SQL Server 2012 instance have only authorized privileges. Right-click the binaries (\binn) folder, click Properties. On the Security tab, verify that at most the following permissions are present:
Trusted Installer (Full Control)
CREATOR OWNER (Full Control)
SYSTEM (Full Control)
Administrators (Full Control) [See Note 3]
Users (Read, List Folder Contents, Read & Execute)
Creator Owner (Special Permissions - Full control - Subfolders and files only)
All Application Packages (Read & Execute) [Only as needed - see Note 4]
SQL Server Service SID OR Service Account (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Full Control) [Notes 1, 2]
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use. (Read & Execute) [Notes 1, 2]
System Administrators (Full Control) [Note 3]

If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

Right-click each folder under the binaries folder; click Properties. On the Security tab, verify that at most the permissions listed in the preceding paragraph are present.
If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

Right-click the \Install folder, which is a peer of \binn, under ...\MSSQL. On the Security tab, verify that at most the permissions listed in the preceding paragraphs are present. If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.


Locate the ...\Microsoft SQL Server\110\Shared folder, either by stepping up the tree in Windows Explorer or by finding the file path in the registry at:
HKEY_LOCAL_MACHINE
>> SOFTWARE
>> Microsoft
>> Microsoft SQL Server
>> 110
>> SharedCode

Right-click on the ...\110\Shared folder; click Properties. On the Security tab, verify that at most the following permissions are present:
Trusted Installer (Full Control)
CREATOR OWNER (Full Control)
System (Full Control)
SQL Server Service SID OR Service Account (Read & Execute) [Notes 1, 2]
System Administrators (Full Control) [Note 3]
Local Administrators (Read)
SQL Server Analysis Services (SSAS) Service SID or Service Account, if SSAS is in use (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use. (Read, Write) [Notes 1, 2]
Users (Read, List Folder Contents, Read & Execute)
[MsDtsServer110 (Read & Execute) is also permitted, if SSIS/DTS is in use.]
[NT AUTHORITY\NETWORK SERVICE (Read & Execute) may also be required for SQL Server Configuration Manager to operate.]

If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

Right-click each folder under the ...\110\Shared folder; click Properties. On the Security tab, verify that at most the permissions listed in the preceding paragraph are present. If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

-----

Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control because these permissions are available only to the specific service when it is running and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.110).aspx.

Note 2: Tips for adding a service SID/virtual account to a folder's permission list.
1) In Windows Explorer, right-click on the folder and select "Properties."
2) Select the "Security" tab
3) Click "Edit"
4) Click "Add"
5) Click "Locations"
6) Select the computer name
7) Search for the name
7.a) SQL Server Service
7.a.i) Type "NT SERVICE\MSSQL" and click "Check Names". (What you have just typed in is the first 16 characters of the name. At least one character must follow "NT SERVICE\"; you will be presented with a list of all matches. If you have typed in the full, correct name, step 7.a.ii is bypassed.)
7.a.ii) Select the "MSSQL$<instance name>" user and click "OK"
7.b) SQL Agent Service
7.b.i) Type "NT SERVICE\SQL" and click "Check Names"
7.b.ii) Select the "SQLAgent$<instance name>" user and click "OK"
8) Click "OK"
9) Permission like a normal user from here

Note 3: In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (create a custom group for these) and providing the local Administrators group with Read access only. 

Note 4: Some files also require 'ALL APPLICATION PACKAGES (READ, EXECUTE)' permissions for certain functionality to work appropriately, and this is considered acceptable where those permissions are required. (All SQL Server files that require this access reside by default in the ..\Microsoft SQL Server\110\ directory.))
  desc 'fix', %q(Navigate to the SQL Server software directory (\binn) location. Right-click the folder, click Properties. On the Security tab, modify the security permissions, so that files and folders that are part of the SQL Server 2012 installation have at most the following privileges. Right-click each folder under the installation folder, click Properties. On the Security tab, modify the security permissions, so that at most the following permissions are present:
Trusted Installer (Full Control)
CREATOR OWNER (Full Control)
SYSTEM (Full Control)
Administrators (Full Control) [See Note 3]
Users (Read, List Folder Contents, Read & Execute)
Creator Owner (Special Permissions - Full control - Subfolders and files only)
All Application Packages (Read & Execute) [Only as needed - see Note 4]
SQL Server Service SID OR Service Account (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Full Control) [Notes 1, 2]
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use. (Read & Execute) [Notes 1, 2]
System Administrators (Full Control) [Note 3]
Repeat the above for the \Install folder.

Navigate to the ...\Microsoft SQL Server\110\Shared folder. On the Security tab, modify the security permissions, so that at most the following permissions are present:
Trusted Installer (Full Control)
CREATOR OWNER (Full Control)
System (Full Control)
SQL Server Service SID OR Service Account (Read & Execute) [Notes 1, 2]
System Administrators (Full Control) [Note 3]
Local Administrators (Read)
SQL Server Analysis Services (SSAS) Service SID or Service Account, if SSAS is in use (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use. (Read, Write) [Notes 1, 2]
Users (Read, List Folder Contents, Read & Execute)
[MsDtsServer110 (Read & Execute) is also permitted, if SSIS/DTS is in use.]
[NT AUTHORITY\NETWORK SERVICE (Read & Execute) may also be required for SQL Server Configuration Manager to operate.]

-----

Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control because these permissions are available only to the specific service when it is running and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.110).aspx.

Note 2: Tips for adding a service SID/virtual account to a folder's permission list.
1) In Windows Explorer, right-click on the folder and select "Properties."
2) Select the "Security" tab
3) Click "Edit"
4) Click "Add"
5) Click "Locations"
6) Select the computer name
7) Search for the name
7.a) SQL Server Service
7.a.i) Type "NT SERVICE\MSSQL" and click "Check Names". (What you have just typed in is the first 16 characters of the name. At least one character must follow "NT SERVICE\"; you will be presented with a list of all matches. If you have typed in the full, correct name, step 7.a.ii is bypassed.)
7.a.ii) Select the "MSSQL$<instance name>" user and click "OK"
7.b) SQL Agent Service
7.b.i) Type "NT SERVICE\SQL" and click "Check Names"
7.b.ii) Select the "SQLAgent$<instance name>" user and click "OK"
8) Click "OK"
9) Permission like a normal user from here

Note 3: In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (create a custom group for these) and providing the local Administrators group with Read access only. 

Note 4: Some files also require 'ALL APPLICATION PACKAGES (READ, EXECUTE)' permissions for certain functionality to work appropriately, and this is considered acceptable where those permissions are required. (All SQL Server files that require this access reside by default in the ..\Microsoft SQL Server\110\ directory.))
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47599r15_chk'
  tag severity: 'medium'
  tag gid: 'V-40944'
  tag rid: 'SV-53298r8_rule'
  tag stig_id: 'SQL2-00-015800'
  tag gtitle: 'SRG-APP-000133-DB-000207'
  tag fix_id: 'F-46226r15_fix'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001499']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9', 'CM-5 (6)']
end
