control 'SV-69105' do
  title 'The OS must limit privileges to the SQL Server Data Root directory and its subordinate directories and files.'
  desc 'Default database file locations should be protected from unauthorized access.  The system databases, essential to SQL Server operation, are typically located here.'
  desc 'check', %q(Obtain the SQL Server default data directory location: from a command prompt, open the registry editor by typing regedit.exe, and pressing [ENTER]. Navigate to the following registry location:
HKEY_LOCAL_MACHINE
>> SOFTWARE
>> Microsoft
>> Microsoft SQL Server
>> [INSTANCE NAME]
>> Setup
>> SqlDataRoot

In the registry tree, the [INSTANCE NAME] for a SQL Server 2012 database engine instance is normally shown as "MSSQL11" followed by a period and the name that was specified for the SQL Server service at installation time. If multiple SQL Server instances are installed, each will have its own [INSTANCE NAME] node and subtree in the registry.

The value in the Data column for the SqlDataRootregistry entry is the default file system path for the SQL Server 2012 data files. Navigate to that folder location using a command prompt or Windows Explorer. The following instructions assume that Windows Explorer is used.

Determine whether a DefaultData registry entry also exists. Repeat the above for the path:
...[INSTANCE NAME]
>> MSSQLServer
>> DefaultData

Verify that the identified folder(s) and their contents have only authorized privileges. Right-click the folder, click Properties. On the Security tab, verify that at most the following permissions are present:
CREATOR OWNER (Full Control)
System (Full control)
SQL Server Service SID OR Service Account (Full Control) [Notes 1, 2]
System Administrators (Full Control) [Note 3]
SQL Server Analysis Services (SSAS) Service SID or Service Account, if SSAS is in use (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2, 4]
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use. (Read, Execute, Write) [Notes 1, 2]
If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

Right-click each folder, if any, under the above folder(s); click Properties. On the Security tab, verify that at most the permissions listed in the preceding paragraph are present. If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

-----

Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically-generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control because these permissions are available only to the specific service when it is running and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.110).aspx.

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
7.a.ii) Select the "MSSQL$<instance name>" user and click OK
7.b) SQL Agent Service
7.b.i) Type "NT SERVICE\SQL" and click "Check Names"
7.b.ii) Select the "SQLAgent$<instance name>" user and click OK
8) Click OK
9) Permission like a normal user from here

Note 3: In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (create a custom group for these) and providing the local Administrators group with Read access only.

Note 4: It may also be necessary to grant the SQL Server Agent permission to Delete the \Log directory and its contents.  This is not a finding.)
  desc 'fix', %q(Navigate to the identified folder location(s). Right-click the folder, click Properties. On the Security tab, modify the security permissions so that files and folders have at most the permissions listed below. Right-click each folder under the identified folder(s), click Properties. On the Security tab, modify the security permissions so that at most the following permissions are present.
CREATOR OWNER (Full Control)
System (Full control)
SQL Server Service SID OR Service Account (Full Control) [Notes 1, 2]
System Administrators (Full Control) [Note 3]
SQL Server Analysis Services (SSAS) Service SID or Service Account, if SSAS is in use (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2, 4]
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use. (Read, Execute, Write) [Notes 1, 2]

-----

Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically-generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control because these permissions are available only to the specific service when it is running and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.110).aspx.

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
7.a.ii) Select the "MSSQL$<instance name>" user and click OK
7.b) SQL Agent Service
7.b.i) Type "NT SERVICE\SQL" and click "Check Names"
7.b.ii) Select the "SQLAgent$<instance name>" user and click OK
8) Click OK
9) Permission like a normal user from here

Note 3: In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (create a custom group for these) and providing the local Administrators group with Read access only.

Note 4: It may also be necessary to grant the SQL Server Agent permission to Delete the \Log directory and its contents.)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-55479r6_chk'
  tag severity: 'medium'
  tag gid: 'V-54859'
  tag rid: 'SV-69105r5_rule'
  tag stig_id: 'SQL2-00-025100'
  tag gtitle: 'SRG-APP-000133-DB-000207'
  tag fix_id: 'F-59715r9_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
