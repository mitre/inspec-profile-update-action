control 'SV-213822' do
  title 'The audit information produced by SQL Server must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft or unauthorized modification of sensitive data stored in the database.'
  desc 'check', %q(Obtain the SQL Server audit file location(s) by running the following SQL script:
SELECT DISTINCT
LEFT(path, (LEN(path) - CHARINDEX('\',REVERSE(path)) + 1)) AS "Audit Path"
FROM sys.traces
UNION
SELECT log_file_path AS "Audit Path"
FROM sys.server_file_audits

For each audit, the path column will give the location of the file.

Verify that all audit files have the correct permissions by doing the following for each audit file: Navigate to audit folder location(s) using a command prompt or Windows Explorer.

Right-click the file/folder, click Properties. On the Security tab, verify that at most the following permissions are applied:
Administrator(read)
Users (none)
Audit Administrator (Full Control)
Auditors group (Read)
SQL Server Service SID OR Service Account (Full Control) [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]

If any less restrictive permissions are present and not specifically justified and approved in the system security plan, this is a finding. 

If less restrictive permissions are present and specifically justified and approved in the system security plan, this is not a finding.

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
  desc 'fix', %q(Modify audit file permissions to meet the requirement to protect against unauthorized deletion.

Navigate to audit folder location(s) using a command prompt or Windows Explorer. Right-click on the file, click Properties.
On the Security tab, modify the security permissions to:
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
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15041r312817_chk'
  tag severity: 'medium'
  tag gid: 'V-213822'
  tag rid: 'SV-213822r395826_rule'
  tag stig_id: 'SQL4-00-013800'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-15039r312818_fix'
  tag 'documentable'
  tag legacy: ['SV-82283', 'V-67793']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
