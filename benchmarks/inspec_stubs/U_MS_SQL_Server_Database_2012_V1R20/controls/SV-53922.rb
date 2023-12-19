control 'SV-53922' do
  title 'Administrative privileges, built-in server roles and built-in database roles must be assigned to the DBMS login accounts that require them via custom roles, and not directly.'
  desc 'SQL Server must employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Privileges granted outside the role of the application user job function are more likely to go unmanaged or without oversight for authorization. Maintenance of privileges using roles defined for discrete job functions offers improved oversight of application user privilege assignments and helps to protect against unauthorized privilege assignment.

SQL Server built-in administrative privileges, built-in server roles and built-in database roles must not be assigned directly to administrative user accounts (that is, server logins and database users). If administrative user accounts have direct access to administrative roles, this access must be removed, with the exception of administrative roles that the DBMS assigns to the special database principal [dbo], and will not allow to be altered.

The built-in server role "sysadmin" is a partial exception. This cannot be granted to a user-defined role, only to a login account. Most (not necessarily all) database administrators will need to be members of sysadmin. Without this, most DBCC commands and the system stored procedures/functions listed below are unavailable. The users who require such access must be documented and approved.'
  desc 'check', %q(Check administrative accounts for direct database role membership:

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> User Mapping >> <'highlight database'> >> review 'Database role membership' for each database.

If any administration accounts have a direct privilege to any 'Database role membership' that is part of the SQL Server system, this is a finding.

Check administrative accounts for direct server role membership:

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> Server Roles.

If any administration accounts have direct access to any 'Server roles' privilege that is part of the SQL Server system, this is a finding.

The special database principal [dbo] is an exception.  It is mapped to the server login that is the database owner.  Some roles cannot be mapped to it or unmapped from it.  These role assignments are not a finding.

The built-in server role "sysadmin" is a partial exception.  See the Vulnerability Discussion.)
  desc 'fix', %q(Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> User Mapping >> <'highlight the database'> >> review 'Database role membership' each database.

Remove 'Database role membership' by clicking the appropriate check box.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> Server Roles.

Remove 'Server roles' by clicking the appropriate check box.

The special database principal [dbo] is an exception.  It is mapped to the server login that is the database owner.  Some roles cannot be mapped to it or unmapped from it.

The built-in server role "sysadmin" is a partial exception.  See the Vulnerability Discussion.)
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47934r9_chk'
  tag severity: 'medium'
  tag gid: 'V-41397'
  tag rid: 'SV-53922r5_rule'
  tag stig_id: 'SQL2-00-009500'
  tag gtitle: 'SRG-APP-000062-DB-000034'
  tag fix_id: 'F-46822r5_fix'
  tag cci: ['CCI-002220']
  tag nist: ['AC-5 b']
end
