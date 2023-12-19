control 'SV-224132' do
  title 'The EDB Postgres Advanced Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies.

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', 'Review the system security plan or equivalent documentation to determine the allowed permissions on database objects for each database role or user as well as the database authentication methods that are allowed for each role or user. If this documentation is missing, this is a finding.

Review the permissions actually in place for the EDB postgres cluster (i.e., instance).

First check the privileges of all users and roles in the database by running the following command from the Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "\\du"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If any users or roles have privileges that exceed those that are documented, this is a finding.

Next check the privileges that have been granted on the tables, views, and sequences in the database by running the following command from the Windows command prompt for each database in the EDB postgres instance:

 psql -d <database name> -U <database superuser name> -c "\\dp"

If the privileges assigned to these objects for any users or roles exceeds those that have been documented, this is a finding.

Next as a user that has permission to view the contents of the pg_hba.conf file, review the authentication settings that are configured in that file.

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running EDB postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If any entries do not match the documented authentication requirements, this is a finding.'
  desc 'fix', 'Use GRANT, REVOKE, ALTER statements to add and remove permissions on database objects, bringing them into line with the documented requirements.

To change authentication requirements for the database, as a user with permissions to edit the pg_hba.conf, edit the entries in the file to comply with the documented organizational authentication requirements. See the official PostgreSQL documentation for the complete list of options for authentication: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25805r495416_chk'
  tag severity: 'high'
  tag gid: 'V-224132'
  tag rid: 'SV-224132r836872_rule'
  tag stig_id: 'EP11-00-000800'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-25793r495417_fix'
  tag 'documentable'
  tag legacy: ['SV-109395', 'V-100291']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
