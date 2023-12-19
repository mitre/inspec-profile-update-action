control 'SV-69125' do
  title 'The OS must limit privileges to the SQL Server data directories and their subordinate directories and files.'
  desc 'Database files must be protected from unauthorized access.  Although default data locations are created at installation time, sites can, and will, use other directories for site-created database files to comply with best practices.'
  desc 'check', %q(Obtain the SQL Server data directory location(s): in a tool such as SQL Server Management Studio, run the statement:
SELECT DISTINCT 
LEFT(physical_name, (LEN(physical_name) - CHARINDEX('\',REVERSE(physical_name)) + 1 )) 
AS "Database Data File Paths",
type_desc
FROM sys.master_files
WHERE database_id > 4 
AND type = 0

The query result is a list of file systems locations used for databases other than the system databases.  Navigate to each of those folder locations using a command prompt or Windows Explorer.  The following instructions assume that Windows Explorer is used.


Verify that the identified folders and their contents have only authorized privileges. Right-click each folder, click Properties. On the Security tab, verify that at most the following permissions are present:
CREATOR OWNER (Full Control)
System (Full control)
SQL Server Service SID OR Service Account (Full Control)  [Notes 1, 2]  
System Administrators (Full Control)  [Note 3]
SQL Server Analysis Services (SSAS) Service SID or Service Account, if SSAS is in use (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write)  [Notes 1, 2]  
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use.  (Read, Write)  [Notes 1, 2]  
If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.)
  desc 'fix', %q(Navigate to the identified folder location(s).  Right-click the folder, click Properties.  On the Security tab, modify the security permissions so that files and folders have at most the permissions listed below. Right-click each folder under the identified folder(s), click Properties. On the Security tab, modify the security permissions so that at most the following permissions are present.
CREATOR OWNER (Full Control)
System (Full control)
SQL Server Service SID OR Service Account (Full Control)  [Notes 1, 2]  
SQL Server Analysis Services (SSAS) Service SID or Service Account, if SSAS is in use (Read & Execute) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write)  [Notes 1, 2]  
SQL Server FD Launcher Service SID OR Service Account, if full-text indexing is in use.  (Read, Write)  [Notes 1, 2]  
System Administrators (Full Control)  [Note 3]


-----

Note 1:  It is highly advisable to use a separate account for each service.  When installing SQL Server in single-server mode, you can opt to have these provisioned for you.  These automatically-generated accounts are referred to as virtual accounts.  Each virtual account has an equivalent Service SID, with the same name.  The installer also creates an equivalent SQL Server login, also with the same name.  Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control because these permissions are available only to the specific service when it is running and not in any other context.  (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.)  For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.110).aspx.


Note 2:  Tips for adding a service SID/virtual account to a folder's permission list.
1) In Windows Explorer, right-click on the folder and select "Properties."
2) Select the "Security" tab
3) Click "Edit"
4) Click "Add"
5) Click "Locations"
6) Select the computer name
7) Search for the name
7.a) SQL Server Service
7.a.i) Type "NT SERVICE\MSSQL" and click "Check Names".  (What you have just typed in is the first 16 characters of the name.  At least one character must follow "NT SERVICE\"; you will be presented with a list of all matches.  If you have typed in the full, correct name, step 7.a.ii is bypassed.)
7.a.ii) Select the "MSSQL$<instance name>" user and click OK
7.b) SQL Agent Service
7.b.i) Type "NT SERVICE\SQL" and click "Check Names"
7.b.ii) Select the "SQLAgent$<instance name>" user and click OK
8) Click OK
9) Permission like a normal user from here


Note 3:  In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (create a custom group for these) and providing the local Administrators group with Read access only.)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-55505r6_chk'
  tag severity: 'medium'
  tag gid: 'V-54879'
  tag rid: 'SV-69125r3_rule'
  tag stig_id: 'SQL2-00-025200'
  tag gtitle: 'SRG-APP-000133-DB-000207'
  tag fix_id: 'F-59741r9_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
