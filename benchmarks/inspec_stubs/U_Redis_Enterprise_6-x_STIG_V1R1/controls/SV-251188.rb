control 'SV-251188' do
  title 'Redis Enterprise DBMS must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
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

Depending on the capabilities of the DBMS and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of DBMS security features, database triggers, other mechanisms, or a combination of these.

Redis Enterprise comes with a configurable role-based access control mechanism that allows users to be given specific roles. These roles provide various levels of permissions to security safeguards and countermeasures.'
  desc 'check', 'To verify this, perform the following steps:
1. Log in to the Redis Enterprise control plane.
2. Navigate to the access control tab.
3. Navigate to the users tab and review the roles for users.
4. For users without the need to modify the database, verify they are given a viewer or none for cluster management in the roles tab.
5. For users with access to databases, verify they are given the default role "Not Dangerous" or a more restrictive role that does not allow access to the dangerous command category.

If a non-privileged user is granted a non-default role, this is a finding.'
  desc 'fix', "To ensure that a non-privileged user is not granted a non-default role, perform the following steps:
1. Log in to the Redis Enterprise control plane.
2. Navigate to the access control tab.
3. Navigate to the users tab and review the roles for users.
4. Assign users an appropriate role, and if necessary, create a new role for the user.
5. Modify and save the users' new role after ensuring the role is provided with the appropriate permissions."
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54623r804752_chk'
  tag severity: 'medium'
  tag gid: 'V-251188'
  tag rid: 'SV-251188r804754_rule'
  tag stig_id: 'RD6X-00-001000'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-54577r804753_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
