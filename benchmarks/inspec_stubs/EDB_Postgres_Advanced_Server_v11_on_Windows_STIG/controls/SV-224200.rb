control 'SV-224200' do
  title 'The EDB Postgres Advanced Server must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

DBMS functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

The DBMS must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.'
  desc 'check', %q(If EDB Postgres supports only software development, experimentation, and/or developer-level testing (that is, excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding.

Review the EDB Postgres security settings with respect to non-administrative users' ability to create, alter, or replace logic modules, to include but not necessarily only stored procedures, functions, triggers, and views. These following commands, which are run using psql, can help with showing existing permissions of databases and schemas:

\l
\dn+

Permissions of concern in this respect include the following, and possibly others:
 - any database or schema with "C" (create) or "w" (update) privileges that are not necessary

If any such permissions exist and are not documented and approved, this is a finding.)
  desc 'fix', 'Document and obtain approval for any non-administrative users who require the ability to create, alter, or replace logic modules.

Implement the approved permissions. Revoke (or deny) any unapproved permissions and remove any unauthorized role memberships.

Use the REVOKE SQL command to remove privileges from databases and schemas.

 For example, to revoke create privileges on a database:
 REVOKE CREATE ON DATABASE <database_name > FROM <role_name>;

 To revoke create privileges on a database:
 REVOKE CREATE ON SCHEMA <schema_name> FROM <role_name>;'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25873r495618_chk'
  tag severity: 'medium'
  tag gid: 'V-224200'
  tag rid: 'SV-224200r508023_rule'
  tag stig_id: 'EP11-00-008400'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag fix_id: 'F-25861r495619_fix'
  tag 'documentable'
  tag legacy: ['SV-109525', 'V-100421']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
