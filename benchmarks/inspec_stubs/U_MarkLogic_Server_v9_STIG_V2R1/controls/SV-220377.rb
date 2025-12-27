control 'SV-220377' do
  title 'MarkLogic Server must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
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
  desc 'check', 'Review the MarkLogic system documentation to obtain the definition of the database/DBMS functionality considered privileged in the context of the system in question.

Review MarkLogic users and assigned roles
1. Navigate to the MarkLogic Admin page >> Security >> Roles.
2. Validate user-created roles have appropriate permissions/roles applied.
3. Navigate to the MarkLogic Admin page >> Security >> Users.
4. Verify user-created Users are only granted roles meeting their specific requirements and do not allow for unnecessary elevated privileges.

If Users are assigned roles providing unnecessary elevated or privileged permissions, this is a finding.

If Roles are defined with unnecessary elevated permissions, this is a finding.'
  desc 'fix', 'Review MarkLogic User and Role configurations to ensure correct privileges are assigned and update as required.

1. Navigate to the MarkLogic Admin page >> Security >> Roles.
2. Select specific roles (usually custom defined roles by administrator) and only apply privileges with the least amount of permissions required for a given role.
3. Navigate to the MarkLogic Admin Page >> Security >> Users.
4. Select specific users (usually custom defined users by an administrator) and add/remove roles allowing for the least amount of privileges required for the specified user.
5. Save configuration and repeat for each user-defined User/Role.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22092r401582_chk'
  tag severity: 'medium'
  tag gid: 'V-220377'
  tag rid: 'SV-220377r855481_rule'
  tag stig_id: 'ML09-00-006700'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-22081r401583_fix'
  tag 'documentable'
  tag legacy: ['SV-110103', 'V-100999']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
