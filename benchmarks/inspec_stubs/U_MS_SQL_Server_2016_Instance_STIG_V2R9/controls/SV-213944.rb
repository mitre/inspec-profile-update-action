control 'SV-213944' do
  title 'The audit information produced by SQL Server must be protected from unauthorized access, modification, and deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.  

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.  

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access. SQL Server is an application that is able to view and manipulate audit file data. 

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'If the database is setup to write audit logs using APPLICATION or SECURITY event logs rather than writing to a file, this is N/A.

Obtain the SQL Server audit file location(s) by running the following SQL script:  

SELECT log_file_path AS "Audit Path"  
FROM sys.server_file_audits  

For each audit, the path column will give the location of the file.  

Verify that all audit files have the correct permissions by doing the following for each audit file: Navigate to audit folder location(s) using a command prompt or Windows Explorer.  

Right-click the file/folder and click "Properties". On the "Security" tab, verify that at most the following permissions are applied:  

Administrator (read)  
Users (none)  
Audit Administrator (Full Control)  
Auditors group (Read)  
SQL Server Service SID OR Service Account (Full Control)  
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) 

If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.'
  desc 'fix', %q(Modify audit file permissions to meet the requirement to protect against unauthorized access.  

Application event log and security log permissions are covered in the Windows Server STIGs. Be sure to reference these depending on the OS in use.

Navigate to audit folder location(s) using a command prompt or Windows Explorer. Right-click the file and click "Properties".  

On the Security tab, modify the security permissions to:  
Administrator (read)  
Users (none)  
Audit Administrator(Full Control)  
Auditors group (Read)  
SQL Server Service SID OR Service Account (Full Control) [Notes 1, 2]  
SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write) [Notes 1, 2]  

-----  
Note 1: It is highly advisable to use a separate account for each service. When installing SQL Server in single-server mode, you can opt to have these provisioned for you. These automatically-generated accounts are referred to as virtual accounts. Each virtual account has an equivalent Service SID, with the same name. The installer also creates an equivalent SQL Server login, also with the same name. Applying folder and file permissions to Service SIDs, rather than to domain accounts or local computer accounts, provides tighter control, because these permissions are available only to the specific service when it is running, and not in any other context. (However, when using failover clustering, a domain account must be specified at installation, rather than a virtual account.) For more on this topic, see http://msdn.microsoft.com/en-us/library/ms143504(v=sql.130).aspx.  

Note 2: Tips for adding a service SID/virtual account to a folder's permission list.  

1) In Windows Explorer, right-click the folder and select "Properties".  
2) Select the "Security" tab.  
3) Click "Edit".  
4) Click "Add".  
5) Click "Locations".  
6) Select the computer name.  
7) Search for the name.  
7.a) SQL Server Service  
7.a.i) Type "NT SERVICE\MSSQL" and click "Check Names". (What you have just typed in is the first 16 characters of the name. At least one character must follow "NT SERVICE\"; you will be presented with a list of all matches. If you have typed in the full, correct name, step 7.a.ii is bypassed.)  
7.a.ii) Select the "MSSQL$" user and click "OK".
7.b) SQL Agent Service  
7.b.i) Type "NT SERVICE\SQL" and click "Check Names".  
7.b.ii) Select the "SQLAgent$" user and click "OK". 
8) Click "OK".  
9) Permission like a normal user from here.)
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15161r754588_chk'
  tag severity: 'medium'
  tag gid: 'V-213944'
  tag rid: 'SV-213944r879576_rule'
  tag stig_id: 'SQL6-D0-005900'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-15159r754589_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag 'documentable'
  tag legacy: ['SV-93857', 'V-79151']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
