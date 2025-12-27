control 'SV-235181' do
  title 'The MySQL Database Server 8.0 must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

System documentation should include a definition of the functionality considered privileged.

Depending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

A privileged function in the Database Management System (DBMS)/database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In a SQL environment, it encompasses, but is not necessarily limited to: 
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
  desc 'check', "Review the server documentation to obtain a listing of accounts used for executing external processes. Execute the following query to obtain a listing of accounts currently configured for use by external processes. 

SHOW PROCEDURE STATUS where security_type <> 'INVOKER';
SHOW FUNCTION STATUS where security_type <> 'INVOKER';

If DEFINER accounts are returned that are not documented and authorized, this is a finding.
If elevation of MySQL privileges using DEFINER is documented, but not implemented as described in the documentation, this is a finding.
If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding."
  desc 'fix', 'Remove any procedures that are not authorized.

Drop the procedure or function using 
DROP PROCEDURE <proc_name>;
DROP FUNCTION <function_name>;'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38400r623663_chk'
  tag severity: 'medium'
  tag gid: 'V-235181'
  tag rid: 'SV-235181r879717_rule'
  tag stig_id: 'MYS8-00-010700'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-38363r623664_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
