control 'SV-214067' do
  title 'PostgreSQL must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Review system documentation to identify the required discretionary access control (DAC).

Review the security configuration of the database and PostgreSQL. If applicable, review the security configuration of the application(s) using the database.

If the discretionary access control defined in the documentation is not implemented in the security configuration, this is a finding.

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

To check the ownership of objects in the database, as the database administrator, run the following:

$ sudo su - postgres
$ psql -c "\\dn *.*"
$ psql -c "\\dt *.*"
$ psql -c "\\ds *.*"
$ psql -c "\\dv *.*"
$ psql -c "\\df+ *.*"

If any role is given privileges to objects it should not have, this is a finding.'
  desc 'fix', %q(Implement the organization's DAC policy in the security configuration of the database and PostgreSQL, and, if applicable, the security configuration of the application(s) using the database.

To GRANT privileges to roles, as the database administrator (shown here as "postgres"), run statements like the following examples:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA test"
$ psql -c "GRANT CREATE ON SCHEMA test TO bob"
$ psql -c "CREATE TABLE test.test_table(id INT)"
$ psql -c "GRANT SELECT ON TABLE test.test_table TO bob"

To REVOKE privileges to roles, as the database administrator (shown here as "postgres"), run statements like the following examples:

$ psql -c "REVOKE SELECT ON TABLE test.test_table FROM bob"
$ psql -c "REVOKE CREATE ON SCHEMA test FROM bob")
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15283r360832_chk'
  tag severity: 'medium'
  tag gid: 'V-214067'
  tag rid: 'SV-214067r508027_rule'
  tag stig_id: 'PGS9-00-002200'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-15281r360833_fix'
  tag 'documentable'
  tag legacy: ['V-72883', 'SV-87535']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
