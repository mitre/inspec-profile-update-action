control 'SV-213718' do
  title 'DB2 must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

System documentation should include a definition of the functionality considered privileged.

Depending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

A privileged function in the DBMS/database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to: 

CREATE
ALTER
DROP
GRANT
REVOKE
DENY

There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples include:

TRUNCATE TABLE;
DELETE, or
DELETE affecting more than n rows, for some n, or
DELETE without a WHERE clause;

UPDATE or
UPDATE affecting more than n rows, for some n, or
UPDATE without a WHERE clause;

any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.

Depending on the capabilities of the DBMS and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of DBMS security features, database triggers, other mechanisms, or a combination of these.'
  desc 'check', 'Review the system documentation to obtain the definition of the DB2 functionality considered privileged in the context of the system in question.

Run the following command to find the privileged groups to get the value of SYSADM_GROUP, SYSCTRL_GROUP, SYSMAINT_GROUP, SYSMON_GROUP:
     
     $db2 get dbm cfg 

If non-privileged users are members of any of these groups, this is a finding. 

Run the following SQL command to find the database authorities: 
DB2> SELECT * FROM SYSCAT.DBAUTH

If non-privileged users have any database authority, this is a finding. 

Query the following system catalog views to find out the authorities on all database objects:

SYSCAT.COLAUTH: Lists the column privileges
SYSCAT.DBAUTH: Lists the database privileges
SYSCAT.INDEXAUTH: Lists the index privileges
SYSCAT.MODULEAUTH: Lists the module privileges
SYSCAT.PACKAGEAUTH: Lists the package privileges
SYSCAT.PASSTHRUAUTH: Lists the server privilege
SYSCAT.ROLEAUTH: Lists the role privileges
SYSCAT.ROUTINEAUTH: Lists the routine (functions, methods, and stored procedures) privileges
SYSCAT.SCHEMAAUTH: Lists the schema privileges
SYSCAT.SEQUENCEAUTH: Lists the sequence privileges
SYSCAT.SURROGATEAUTHIDS: Lists the authorization IDs for which another authorization ID can act as a surrogate. 
SYSCAT.TABAUTH: Lists the table and view privileges
SYSCAT.TBSPACEAUTH: Lists the table space privileges
SYSCAT.VARIABLEAUTH: Lists the variable privileges
SYSCAT.WORKLOADAUTH: Lists the workload privileges
SYSCAT.XSROBJECTAUTH: Lists the XSR object privileges

If non-privileged users have any authority, this is a finding.'
  desc 'fix', 'Use appropriate OS utility to remove the non-authorized users form privileged groups.

Use REVOKE command to revoke database level or object privileges from non-authorized users. 

Note: The following views and table functions list information about privileges held by users, identities of users granting privileges, and object ownership:
SYSCAT.COLAUTH: Lists the column privileges
SYSCAT.DBAUTH: Lists the database privileges
SYSCAT.INDEXAUTH: Lists the index privileges
SYSCAT.MODULEAUTH: Lists the module privileges
SYSCAT.PACKAGEAUTH: Lists the package privileges
SYSCAT.PASSTHRUAUTH: Lists the server privilege
SYSCAT.ROLEAUTH: Lists the role privileges
SYSCAT.ROUTINEAUTH: Lists the routine (functions, methods, and stored procedures) privileges
SYSCAT.SCHEMAAUTH: Lists the schema privileges
SYSCAT.SEQUENCEAUTH: Lists the sequence privileges
SYSCAT.SURROGATEAUTHIDS: Lists the authorization IDs for which another authorization ID can act as a surrogate.
SYSCAT.TABAUTH: Lists the table and view privileges
SYSCAT.TBSPACEAUTH: Lists the table space privileges
SYSCAT.VARIABLEAUTH: Lists the variable privileges
SYSCAT.WORKLOADAUTH: Lists the workload privileges
SYSCAT.XSROBJECTAUTH: Lists the XSR object privileges'
  impact 0.7
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14939r295203_chk'
  tag severity: 'high'
  tag gid: 'V-213718'
  tag rid: 'SV-213718r879717_rule'
  tag stig_id: 'DB2X-00-007000'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-14937r295204_fix'
  tag 'documentable'
  tag legacy: ['SV-89239', 'V-74565']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
