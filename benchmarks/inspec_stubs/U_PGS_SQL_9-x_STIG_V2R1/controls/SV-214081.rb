control 'SV-214081' do
  title 'PostgreSQL must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Check PostgreSQL settings to determine whether objects or code implementing security functionality are located in a separate security domain, such as a separate database or schema created specifically for security functionality.

By default, all objects in pg_catalog and information_schema are owned by the database administrator. 

To check the access controls for those schemas, as the database administrator (shown here as "postgres"), run the following commands to review the access privileges granted on the data dictionary and security tables, views, sequences, functions and trigger procedures:

$ sudo su - postgres
$ psql -x -c "\\dp pg_catalog.*"
$ psql -x -c "\\dp information_schema.*"

Repeat the \\dp statements for any additional schemas that contain locally defined security objects.

Repeat using \\df+*.* to review ownership of PostgreSQL functions:

$ sudo su - postgres
$ psql -x -c "\\df+ pg_catalog.*"
$ psql -x -c "\\df+ information_schema.*"

Refer to the PostgreSQL online documentation for GRANT for help in interpreting the Access Privileges column in the output from \\du. Note that an entry starting with an equals sign indicates privileges granted to Public (all users). By default, most of the tables and views in the pg_catalog and information_schema schemas can be read by Public.

If any user besides the database administrator(s) is listed in access privileges and not documented, this is a finding.

If security-related database objects or code are not kept separate, this is a finding.'
  desc 'fix', 'Do not locate security-related database objects with application tables or schema.

Review any site-specific applications security modules built into the database: determine what schema they are located in and take appropriate action.

Do not grant access to pg_catalog or information_schema to anyone but the database administrator(s). Access to the database administrator account(s) must not be granted to anyone without official approval.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15297r360874_chk'
  tag severity: 'medium'
  tag gid: 'V-214081'
  tag rid: 'SV-214081r508027_rule'
  tag stig_id: 'PGS9-00-004000'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-15295r360875_fix'
  tag 'documentable'
  tag legacy: ['V-72911', 'SV-87563']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
