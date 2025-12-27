control 'SV-82281' do
  title 'The audit information produced by  SQL Server must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions, and limiting log data locations.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Modification of database audit data could mask the theft or unauthorized modification of sensitive data stored in the database.'
  desc 'check', %q(Obtain the SQL Server audit file location(s) by running the following SQL script:
SELECT DISTINCT
LEFT(path, (LEN(path) - CHARINDEX('\',REVERSE(path)) + 1)) AS "Audit Path"
FROM sys.traces
UNION
SELECT log_file_path AS "Audit Path"
FROM sys.server_file_audits

For each audit, the Audit Path column will give the location of the file.

Verify that all audit files have the correct permissions by doing the following for each audit file: Navigate to audit folder location(s) using a command prompt or Windows Explorer. The following instructions assume Windows Explorer is used.

Right-click the file/folder, click Properties. On the Security tab, verify that at most the following permissions are applied:
Administrator(read)
Users (none)
Audit Administrator (Full Control)
Auditors group (Read)
SQL Server Service SID OR Service Account (Full Control) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]

If any less restrictive permissions are present and not specifically justified and approved in the system security plan, this is a finding. 

If less restrictive permissions are present and specifically justified and approved in the system security plan, this is not a finding.

If Trace is in use, SQL Server creates each trace file with a standard set of permissions, overriding the folder permissions.  It grants full control to OWNER RIGHTS, Administrators and <SQL Server Instance name>.

Since this is not configurable, this is not a finding.

-----

Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically-generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control, because these permissions are available only to the specific service when it is running, and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.120).aspx.

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
9) Permission like a normal user from here)
  desc 'fix', %q(Edit the system security plan to include justification and authorization for any less restrictive permissions that are present and needed.  (An example might be where Auditors need "Read & Execute" rather than "Read" alone.)

Modify audit file permissions to meet the requirement to protect against unauthorized modification.

Navigate to audit folder location(s) using a command prompt or Windows Explorer. Right-click on the file, click Properties. On the Security tab, modify the security permissions to:
Administrator(read)
Users (none)
Audit Administrator(Full Control)
Auditors group (Read)
SQL Server Service SID OR Service Account (Full Control) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]

-----

Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically-generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control, because these permissions are available only to the specific service when it is running, and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.120).aspx.

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
9) Permission like a normal user from here)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68359r3_chk'
  tag severity: 'medium'
  tag gid: 'V-67791'
  tag rid: 'SV-82281r2_rule'
  tag stig_id: 'SQL4-00-013700'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-73907r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
