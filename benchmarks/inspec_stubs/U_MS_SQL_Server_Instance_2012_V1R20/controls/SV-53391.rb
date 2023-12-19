control 'SV-53391' do
  title 'SQL Server must protect the audit records generated as a result of remote access to privileged accounts and by the execution of privileged functions.'
  desc 'Protection of audit records and audit data is of critical importance. Care must be taken to ensure privileged users cannot circumvent audit protections put in place.

Auditing might not be reliable when performed by an information system that the user being audited has privileged access to.

The privileged user could inhibit auditing or directly modify audit records. To prevent this from occurring, privileged access shall be further defined between audit-related privileges and other privileges, thus limiting the users with audit-related privileges.

Reducing the risk of audit compromises by privileged users can also be achieved, for example, by performing audit activity on a separate information system where the user in question has limited access, or by using storage media that cannot be modified (e.g., write-once recording devices).

If an attacker were to gain access to audit tools, they could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', %q(Obtain the SQL Server audit file location(s) by running the following SQL script:
SELECT DISTINCT 
LEFT(path, (LEN(path) - CHARINDEX('\',REVERSE(path)) + 1)) AS "Audit Path"
FROM sys.traces
UNION
SELECT log_file_path AS "Audit Path"
FROM sys.server_file_audits

For each audit, the path column will give the location of the file.

Verify that all audit files have the correct permissions by doing the following for each audit file: Navigate to audit folder location(s) using a command prompt or Windows Explorer.

Right-click the file/folder, click Properties.  On the Security tab, verify that at most the following permissions are applied:
Administrator(read)
Users (none)
Audit Administrator (Full Control)
Auditors group (Read)
SQL Server Service SID OR Service Account (Full Control)  [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]
If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.)
  desc 'fix', %q(Modify audit file permissions to meet the requirement to protect against unauthorized access.

Navigate to the audit folder location(s) using a command prompt or Windows Explorer.  Right-click on the file, click Properties.
On the Security tab, modify the security permissions to: 
Administrator(read)
Users (none)
Audit Administrator(Full Control)
Auditors group (Read)
SQL Server Service SID OR Service Account (Full Control)  [Notes 1, 2]
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]

-----

Note 1:  It is highly advisable to use a separate account for each service.  When installing SQL Server in single-server mode, you can opt to have these provisioned for you.  These automatically-generated accounts are referred to as virtual accounts.  Each virtual account has an equivalent Service SID, with the same name.  The installer also creates an equivalent SQL Server login, also with the same name.  Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control, because these permissions are available only to the specific service when it is running, and not in any other context.  (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.)  For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.110).aspx.


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
9) Permission like a normal user from here)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47634r5_chk'
  tag severity: 'medium'
  tag gid: 'V-41017'
  tag rid: 'SV-53391r4_rule'
  tag stig_id: 'SQL2-00-014400'
  tag gtitle: 'SRG-APP-000127-DB-000172'
  tag fix_id: 'F-46315r7_fix'
  tag cci: ['CCI-000366', 'CCI-001351']
  tag nist: ['CM-6 b', 'AU-9 (4)']
end
